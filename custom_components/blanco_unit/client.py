"""Defines the bluetooth client to control the Blanco Unit."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
import hashlib
import json
import logging
import math
import random
import time
from typing import Any

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak_retry_connector import establish_connection

from .const import CHARACTERISTIC_UUID, MTU_SIZE
from .data import (
    BlancoUnitIdentity,
    BlancoUnitSettings,
    BlancoUnitStatus,
    BlancoUnitSystemInfo,
    BlancoUnitWifiInfo,
    BlancoUnitWifiNetwork,
)

_LOGGER = logging.getLogger(__name__)

# -------------------------------
# region Exceptions
# -------------------------------


class BlancoUnitClientError(Exception):
    """Base exception for Blanco Unit client errors."""


class BlancoUnitAuthenticationError(BlancoUnitClientError):
    """Exception raised when authentication fails due to wrong PIN."""

    def __init__(self, message: str = "Wrong PIN") -> None:
        """Initialize BlancoUnitAuthenticationError."""
        super().__init__(message)


class BlancoUnitConnectionError(BlancoUnitClientError):
    """Exception raised when connection fails."""

    def __init__(self, message: str = "Connection failed") -> None:
        """Initialize BlancoUnitConnectionError."""
        super().__init__(message)


# -------------------------------
# region Internal Data Models
# -------------------------------


@dataclass
class _RequestMeta:
    """Internal: Request metadata."""

    evt_type: int
    dev_id: str | None = None
    dev_type: int | None = None
    evt_ver: int = 1
    evt_ts: int = field(default_factory=lambda: int(time.time() * 1000))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, omitting None dev_id and dev_type."""
        data = asdict(self)
        if self.dev_id is None:
            del data["dev_id"]
        if self.dev_type is None:
            del data["dev_type"]
        return data


@dataclass
class _RequestBody:
    """Internal: Request body."""

    meta: _RequestMeta
    opts: dict[str, int] | None = None
    pars: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        data = {"meta": self.meta.to_dict()}
        if self.opts:
            data["opts"] = self.opts
        if self.pars is not None:
            data["pars"] = self.pars
        return data


@dataclass
class _RequestEnvelope:
    """Internal: Complete request envelope."""

    session: int
    id: int
    token: str
    salt: str
    body: _RequestBody
    type: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session": self.session,
            "id": self.id,
            "type": self.type,
            "token": self.token,
            "salt": self.salt,
            "body": self.body.to_dict(),
        }


@dataclass
class _SetTemperaturePars:
    """Internal: Parameters for setting cooling temperature."""

    cooling_celsius: int

    def to_pars(self) -> dict[str, Any]:
        """Convert to parameters dictionary."""
        return {
            "set_point_cooling": {"val": self.cooling_celsius},
        }


@dataclass
class _SetHeatingTemperaturePars:
    """Internal: Parameters for setting heating temperature (CHOICE.All only)."""

    heating_celsius: int

    def to_pars(self) -> dict[str, Any]:
        """Convert to parameters dictionary."""
        return {
            "set_point_heating": {"val": self.heating_celsius},
        }


@dataclass
class _SetWaterHardnessPars:
    """Internal: Parameters for setting water hardness."""

    level: int

    def to_pars(self) -> dict[str, Any]:
        """Convert to parameters dictionary."""
        if not (1 <= self.level <= 9):
            raise ValueError("Hardness level must be 1-9")
        return {"wtr_hardness": {"val": self.level}}


@dataclass
class _ChangePinPars:
    """Internal: Parameters for changing PIN."""

    new_pin: str

    def to_pars(self) -> dict[str, Any]:
        """Convert to parameters dictionary."""
        if len(self.new_pin) != 5 or not self.new_pin.isdigit():
            raise ValueError("PIN must be 5 digits")
        return {"new_pass": self.new_pin}


@dataclass
class _DispensePars:
    """Internal: Parameters for dispensing water."""

    amount_ml: int
    co2_intensity: int

    def to_pars(self) -> dict[str, Any]:
        """Convert to parameters dictionary."""
        return {"disp_amt": self.amount_ml, "co2_int": self.co2_intensity}


@dataclass
class _SetCalibrationPars:
    """Internal: Parameters for setting calibration."""

    calib_type: str  # "calib_still_wtr" or "calib_soda_wtr"
    amount: int

    def to_pars(self) -> dict[str, Any]:
        """Convert to parameters dictionary."""
        return {self.calib_type: {"val": self.amount}}


@dataclass
class _ConnectWifiPars:
    """Internal: Parameters for connecting to a WiFi network."""

    ssid: str
    password: str

    def to_pars(self) -> dict[str, Any]:
        """Convert to parameters dictionary."""
        return {"ssid": {"val": self.ssid}, "password": {"val": self.password}}


@dataclass
class _AllowCloudServicesPars:
    """Internal: Parameters for allowing cloud services."""

    rca_id: str = ""

    def to_pars(self) -> dict[str, Any]:
        """Convert to parameters dictionary."""
        return {"rca_id": self.rca_id}


# -------------------------------
# region Protocol Helper
# -------------------------------


class _BlancoUnitProtocol:
    """Internal protocol handler for packet creation, parsing, and communication."""

    def __init__(self, mtu: int = MTU_SIZE) -> None:
        """Initialize protocol handler."""
        self.mtu = mtu
        self.session_id = random.randint(1000000, 9999999)
        self.msg_id_counter = 1

    def calculate_token(self, pin: str, salt: str) -> str:
        """Calculate authentication token from PIN and salt."""
        pin_hash = hashlib.sha256(pin.encode("utf-8")).hexdigest()
        combined = pin_hash + salt
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def create_packets(self, json_data: dict[str, Any], msg_id: int) -> list[bytes]:
        """Create BLE packets from JSON data with fragmentation."""
        payload_str = json.dumps(json_data, separators=(",", ":"))
        payload_bytes = payload_str.encode("utf-8") + b"\x00\xff"

        packets = []
        first_cap = self.mtu - 5
        next_cap = self.mtu - 2

        if len(payload_bytes) <= first_cap:
            total = 1
        else:
            total = 1 + math.ceil((len(payload_bytes) - first_cap) / next_cap)

        # First packet with header
        packets.append(
            bytes([0xFF, 0x00, total, msg_id, 0x00]) + payload_bytes[:first_cap]
        )

        # Subsequent packets
        offset = first_cap
        idx = 1
        while offset < len(payload_bytes):
            end = offset + next_cap
            packets.append(bytes([msg_id, idx]) + payload_bytes[offset:end])
            offset = end
            idx += 1

        return packets

    def parse_response(self, raw_chunks: list[bytes]) -> dict[str, Any]:
        """Parse BLE response chunks into JSON."""
        _LOGGER.debug("Parsing response data: %s", raw_chunks)

        if not raw_chunks or raw_chunks[0][0] != 0xFF:
            raise ValueError("Invalid chunk stream")

        msg_id = raw_chunks[0][3]
        payload = bytearray(raw_chunks[0][5:])

        for c in raw_chunks[1:]:
            if c[0] != msg_id:
                raise ValueError("Chunk message ID mismatch")
            payload.extend(c[2:])

        clean = payload.split(b"\x00")[0]
        try:
            result: dict[str, Any] = json.loads(clean.decode("utf-8"))
            _LOGGER.debug("Parsed response data: %s", result)
            return result  # noqa: TRY300
        except Exception as e:
            _LOGGER.error("JSON parse failed: %s", clean)
            raise ValueError("Failed to parse JSON response") from e

    @staticmethod
    def extract_pars(response: dict[str, Any]) -> dict[str, Any]:
        """Extract parameters from response body."""
        body = response.get("body", {})
        if "pars" in body:
            return body["pars"]
        if body.get("results"):
            return body["results"][0].get("pars", {})
        return {}

    @staticmethod
    def extract_errors(response: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract error list from response."""
        pars = _BlancoUnitProtocol.extract_pars(response)
        return pars.get("errs", [])

    async def read_response_chunks(self, client: BleakClient) -> list[bytes]:
        """Read response chunks from the characteristic."""
        chunks: list[bytes] = []
        expected = 1
        last_data = b""
        attempts = 0
        max_attempts = 60
        consecutive_errors = 0
        read_start = time.time()

        while len(chunks) < expected and attempts < max_attempts:
            try:
                data = await client.read_gatt_char(CHARACTERISTIC_UUID)
                consecutive_errors = 0
                if not data:
                    attempts += 1
                    await asyncio.sleep(0.05)
                    continue
                if data != last_data:
                    last_data = data
                    chunks.append(data)
                    if data[0] == 0xFF:
                        expected = data[2]
                attempts += 1
                await asyncio.sleep(0.05)
            except Exception as e:  # noqa: BLE001
                err_str = str(e)
                if "Not connected" in err_str or "NotConnected" in err_str:
                    _LOGGER.warning("Read failed (disconnected): %s", e)
                    break
                # Transient ATT errors (e.g. 0x0e) mean the device
                # hasn't prepared its response yet — keep polling.
                consecutive_errors += 1
                if consecutive_errors >= 10:
                    _LOGGER.warning(
                        "Read failed %d times, giving up: %s",
                        consecutive_errors, e,
                    )
                    break
                _LOGGER.debug("Transient read error (attempt %d): %s", attempts, e)
                await asyncio.sleep(0.1)
                attempts += 1

        if len(chunks) != expected:
            elapsed = time.time() - read_start
            _LOGGER.warning(
                "Incomplete BLE response after %d attempts (%.1fs): "
                "got %d/%d chunks",
                attempts, elapsed, len(chunks), expected,
            )
            raise TimeoutError(
                f"Incomplete response: got {len(chunks)}/{expected} chunks "
                f"after {attempts} attempts ({elapsed:.1f}s)"
            )

        elapsed = time.time() - read_start
        _LOGGER.debug(
            "Read %d/%d chunks in %d attempts (%.1fs)",
            len(chunks), expected, attempts, elapsed,
        )
        return chunks

    async def send_pairing_request(
        self, client: BleakClient, pin: str
    ) -> dict[str, Any]:
        """Send pairing request and return parsed response."""
        meta = _RequestMeta(evt_type=10, dev_id=None, dev_type=None)
        body = _RequestBody(meta=meta, pars={})

        req_id = random.randint(1000000, 9999999)
        salt = f"{self.session_id}{req_id}"
        token = self.calculate_token(pin, salt)

        envelope = _RequestEnvelope(
            session=self.session_id, id=req_id, token=token, salt=salt, body=body
        )

        # Increment message ID counter (1-255)
        self.msg_id_counter = (self.msg_id_counter % 254) + 1

        request_dict = envelope.to_dict()
        packets = self.create_packets(request_dict, self.msg_id_counter)

        _LOGGER.debug("Sending pairing data: %s", request_dict)
        _LOGGER.debug("Sending pairing request (ReqID: %s)", req_id)

        # Send packets
        for packet in packets:
            await client.write_gatt_char(CHARACTERISTIC_UUID, packet, response=True)

        # Delay to let device process before polling reads
        await asyncio.sleep(0.3)

        # Read response
        chunks = await self.read_response_chunks(client)
        return self.parse_response(chunks)

    async def send_request(
        self,
        client: BleakClient,
        pin: str,
        dev_id: str,
        dev_type: int,
        evt_type: int,
        ctrl: int | None = None,
        pars: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a general request and return parsed response."""
        meta = _RequestMeta(evt_type=evt_type, dev_id=dev_id, dev_type=dev_type)
        opts_dict: dict[str, int] | None = {"ctrl": ctrl} if ctrl is not None else None
        body = _RequestBody(meta=meta, opts=opts_dict, pars=pars)

        req_id = random.randint(1000000, 9999999)
        salt = f"{self.session_id}{req_id}"
        token = self.calculate_token(pin, salt)

        envelope = _RequestEnvelope(
            session=self.session_id,
            id=req_id,
            token=token,
            salt=salt,
            body=body,
        )

        # Increment message ID counter (1-255)
        self.msg_id_counter = (self.msg_id_counter % 254) + 1

        request_dict = envelope.to_dict()
        packets = self.create_packets(request_dict, self.msg_id_counter)

        _LOGGER.debug("Sending data: %s from %s", request_dict, body)
        _LOGGER.debug("Sending request (ReqID: %s, %d packets)", req_id, len(packets))

        # Send packets
        for packet in packets:
            await client.write_gatt_char(CHARACTERISTIC_UUID, packet, response=True)

        # Delay to let device process before polling reads
        await asyncio.sleep(0.3)

        # Read response
        chunks = await self.read_response_chunks(client)
        return self.parse_response(chunks)


# -------------------------------
# region Client Implementation
# -------------------------------


class BlancoUnitBluetoothClient:
    """Bluetooth client for controlling the Blanco Unit.

    Handles connection, authentication, and all device operations.
    """

    def __init__(
        self,
        pin: str,
        device: BLEDevice,
        connection_callback: Callable[[bool], None],
    ) -> None:
        """Initialize the Blanco Unit Bluetooth client.

        Args:
            pin: The 5-digit PIN code for authentication.
            device: The BLEDevice instance representing the Blanco Unit.
            connection_callback: Callback for connection state changes.
        """
        if len(pin) != 5 or not pin.isdigit():
            raise ValueError("PIN must be exactly 5 digits")

        self._pin = pin
        self._device = device
        self._connection_callback = connection_callback
        self._session_data: _BlancoUnitSessionData | None = None
        self._connect_lock = asyncio.Lock()

    def update_device(self, device: BLEDevice) -> None:
        """Update the BLE device reference with a fresh advertisement."""
        self._device = device

    @property
    def device_id(self) -> str | None:
        """Return the device ID from the current session, or None if not connected."""
        return self._session_data.dev_id if self._session_data else None

    @property
    def device_type(self) -> int | None:
        """Return the device type from the current session, or None if not connected."""
        return self._session_data.dev_type if self._session_data else None

    @property
    def is_connected(self) -> bool:
        """Return True if the BLE client is currently connected."""
        return self._session_data is not None and self._session_data.client.is_connected

    # -------------------------------
    # region Connection Management
    # -------------------------------

    async def disconnect(self) -> None:
        """Disconnect from the Blanco Unit BLE device if connected."""
        await self._clear_session()

    async def _clear_session(self) -> None:
        """Disconnect the BLE client and reset session state.

        MUST be called instead of just setting _session_data = None,
        otherwise the orphaned BleakClient keeps a half-dead BlueZ
        connection alive and subsequent reconnects fail with
        'Service Discovery has not been performed yet'.
        """
        session = self._session_data
        self._session_data = None
        if session is not None:
            _LOGGER.debug(
                "Clearing session and disconnecting BLE client for %s",
                self._device.address,
            )
            try:
                await session.client.disconnect()
            except Exception:  # noqa: BLE001
                _LOGGER.debug(
                    "Ignoring error during session disconnect for %s",
                    self._device.address,
                )

    async def _connect(self) -> _BlancoUnitSessionData:
        """Connect to the device if not already connected and authenticate.

        establish_connection already handles BLE-level retries internally,
        so we only retry here if the *protocol-level* pairing fails after
        a successful BLE connection (e.g. the device dropped the link
        during the pairing handshake).
        """
        async with self._connect_lock:
            if self._session_data:
                _LOGGER.debug("Already connected to %s", self._device.address)
                return self._session_data

            _LOGGER.info(
                "Connecting to %s (name=%s)",
                self._device.address,
                self._device.name or "Unknown",
            )

            # Explicitly disconnect any stale BlueZ connection before
            # attempting a new one.  Without this, BlueZ can hold a
            # half-open D-Bus link that causes persistent ATT 0x0e
            # errors until HA is restarted.
            await self._reset_bluez_connection()

            # Ensure BLE-level bonding — the device requires an encrypted
            # link before it exposes GATT characteristics.
            from .bluez_helpers import async_ensure_bonded  # noqa: PLC0415

            await async_ensure_bonded(self._device.address, self._pin)

            connect_start = time.time()
            last_err: BaseException | None = None
            for attempt in range(2):
                client: BleakClient | None = None
                try:
                    _LOGGER.debug(
                        "Connection attempt %d/2 to %s",
                        attempt + 1, self._device.address,
                    )
                    client = await establish_connection(
                        client_class=BleakClient,
                        device=self._device,
                        name=self._device.name or "Unknown Device",
                        disconnected_callback=self._handle_disconnect,
                        timeout=30,
                        ble_device_callback=lambda: self._device,
                    )
                    _LOGGER.debug(
                        "BLE link established to %s, performing pairing",
                        self._device.address,
                    )

                    # Create protocol instance for this session
                    protocol = _BlancoUnitProtocol(mtu=MTU_SIZE)

                    # Perform initial pairing
                    result = await self._perform_pairing(client, protocol)

                    elapsed = time.time() - connect_start
                    _LOGGER.info(
                        "Connected and paired to %s (dev_id=%s, dev_type=%d) in %.1fs",
                        self._device.address,
                        result.dev_id,
                        result.dev_type,
                        elapsed,
                    )
                    self._session_data = _BlancoUnitSessionData(
                        client=client,
                        dev_id=result.dev_id,
                        dev_type=result.dev_type,
                        protocol=protocol,
                    )
                    self._connection_callback(
                        self._session_data.client.is_connected
                    )
                    return self._session_data
                except BlancoUnitAuthenticationError:
                    # Wrong PIN — no point retrying
                    _LOGGER.warning(
                        "Authentication failed for %s — wrong PIN",
                        self._device.address,
                    )
                    if client is not None:
                        try:
                            await client.disconnect()
                        except Exception:  # noqa: BLE001
                            pass
                    raise
                except (Exception, asyncio.CancelledError) as err:
                    last_err = err
                    _LOGGER.warning(
                        "Connection attempt %d/2 to %s failed: %r",
                        attempt + 1, self._device.address, err,
                    )
                    if client is not None:
                        try:
                            await client.disconnect()
                        except Exception:  # noqa: BLE001
                            pass
                    # Longer backoff to let BlueZ fully release resources
                    await asyncio.sleep(5.0)

            elapsed = time.time() - connect_start
            _LOGGER.warning(
                "All connection attempts to %s exhausted after %.1fs: %r",
                self._device.address, elapsed, last_err,
            )

            # Final fallback: the device may be bonded on the host
            # (BlueZ) but the bond was invalidated on the device side
            # (e.g. integration was removed and re-added, device was
            # factory-reset, or re-paired with the Blanco app).  In
            # that case BLE connects but every GATT operation fails
            # with encryption / ATT 0x0e errors.  Force-clear the
            # BlueZ bond and re-pair, then try one more time.
            if not isinstance(last_err, BlancoUnitAuthenticationError):
                try:
                    repaired = await self._force_repair()
                except Exception:  # noqa: BLE001
                    _LOGGER.debug(
                        "Force re-pair raised", exc_info=True
                    )
                    repaired = False
                if repaired:
                    client = None
                    try:
                        _LOGGER.info(
                            "Retrying connection to %s after forced re-pair",
                            self._device.address,
                        )
                        client = await establish_connection(
                            client_class=BleakClient,
                            device=self._device,
                            name=self._device.name or "Unknown Device",
                            disconnected_callback=self._handle_disconnect,
                            timeout=30,
                            ble_device_callback=lambda: self._device,
                        )
                        protocol = _BlancoUnitProtocol(mtu=MTU_SIZE)
                        result = await self._perform_pairing(client, protocol)
                        elapsed = time.time() - connect_start
                        _LOGGER.info(
                            "Connected and paired to %s after forced "
                            "re-pair (dev_id=%s, dev_type=%d) in %.1fs",
                            self._device.address,
                            result.dev_id,
                            result.dev_type,
                            elapsed,
                        )
                        self._session_data = _BlancoUnitSessionData(
                            client=client,
                            dev_id=result.dev_id,
                            dev_type=result.dev_type,
                            protocol=protocol,
                        )
                        self._connection_callback(
                            self._session_data.client.is_connected
                        )
                        return self._session_data
                    except BlancoUnitAuthenticationError:
                        if client is not None:
                            try:
                                await client.disconnect()
                            except Exception:  # noqa: BLE001
                                pass
                        raise
                    except (Exception, asyncio.CancelledError) as err:
                        last_err = err
                        _LOGGER.warning(
                            "Connection retry after re-pair failed: %r", err
                        )
                        if client is not None:
                            try:
                                await client.disconnect()
                            except Exception:  # noqa: BLE001
                                pass

            raise BlancoUnitConnectionError(
                f"Failed after 2 connection attempts: {last_err}"
            )

    async def _force_repair(self) -> bool:
        """Remove the BlueZ bond for this device and re-pair from scratch.

        Used as a last-resort recovery when the device appears to be
        bonded on the host but every connect attempt fails (typically
        because the device-side bond was invalidated outside HA, e.g.
        the integration was previously removed and re-added).
        """
        from .bluez_helpers import (  # noqa: PLC0415
            async_pair_bluez_device,
            async_remove_bluez_device,
        )

        address = self._device.address
        _LOGGER.warning(
            "Forcing BlueZ re-pair for %s (clearing stale bond)", address
        )
        await async_remove_bluez_device(address)
        # Give BlueZ time to release resources before re-pairing.
        await asyncio.sleep(2.0)
        return await async_pair_bluez_device(address, self._pin)

    async def _reset_bluez_connection(self) -> None:
        """Disconnect any stale BlueZ connection to this device.

        BlueZ can hold a half-open D-Bus connection after an unclean
        disconnect.  This causes persistent ATT 0x0e errors on all
        subsequent connect attempts until HA is restarted.  By
        explicitly calling Disconnect() on the BlueZ device object
        we clear the stale state without requiring a restart.
        """
        try:
            await asyncio.wait_for(self._do_reset_bluez(), timeout=5.0)
        except TimeoutError:
            _LOGGER.debug("_reset_bluez_connection timed out")
        except Exception:  # noqa: BLE001
            pass

    async def _do_reset_bluez(self) -> None:
        """Perform the actual D-Bus reset call."""
        from dbus_fast import BusType  # noqa: PLC0415
        from dbus_fast.aio import MessageBus  # noqa: PLC0415

        address = self._device.address
        dev_path = (
            "/org/bluez/hci0/dev_" + address.upper().replace(":", "_")
        )

        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        try:
            intro = await bus.introspect("org.bluez", dev_path)
            proxy = bus.get_proxy_object("org.bluez", dev_path, intro)
            props = proxy.get_interface(
                "org.freedesktop.DBus.Properties"
            )
            connected = await props.call_get(
                "org.bluez.Device1", "Connected"
            )
            if connected.value:
                _LOGGER.info(
                    "Clearing stale BlueZ connection to %s", address
                )
                device1 = proxy.get_interface("org.bluez.Device1")
                await device1.call_disconnect()
                await asyncio.sleep(0.5)
        finally:
            bus.disconnect()

    def _handle_disconnect(self, client: BleakClient) -> None:
        """Reset session and call connection callback."""
        _LOGGER.warning(
            "Device %s disconnected unexpectedly", self._device.address
        )
        # Only clear if this client matches the current session
        # (avoids clearing a new session established during retry).
        if (
            self._session_data is not None
            and self._session_data.client is client
        ):
            _LOGGER.debug("Cleared session for %s", self._device.address)
            self._session_data = None
        self._connection_callback(False)

    async def _perform_pairing(
        self, client: BleakClient, protocol: _BlancoUnitProtocol
    ) -> PinValidationResult:
        """Perform initial pairing to get device ID and device type.

        Returns:
            Tuple of (dev_id, dev_type).

        Raises:
            BlancoUnitAuthenticationError: If PIN is wrong (error code 4).
            BlancoUnitConnectionError: If device ID cannot be extracted.
        """
        # Validate PIN and get response
        validation = await validate_pin(client, self._pin, protocol)
        if not validation.is_valid:
            raise BlancoUnitAuthenticationError("Wrong PIN - Authentication failed")

        if validation.dev_id is None:
            raise BlancoUnitConnectionError("No device ID in pairing response")

        if validation.dev_type is None:
            raise BlancoUnitConnectionError("No device type in pairing response")
        return validation

    async def _execute_transaction(
        self,
        evt_type: int,
        ctrl: int | None = None,
        pars: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a request-response transaction."""
        session_data = await self._connect()

        _LOGGER.debug(
            "Executing transaction evt_type=%d ctrl=%s to %s",
            evt_type, ctrl, self._device.address,
        )

        try:
            response = await session_data.protocol.send_request(
                client=session_data.client,
                pin=self._pin,
                dev_id=session_data.dev_id,
                dev_type=session_data.dev_type,
                evt_type=evt_type,
                ctrl=ctrl,
                pars=pars,
            )
        except (Exception, asyncio.CancelledError) as err:
            # Connection dropped mid-transaction — disconnect the stale
            # client so BlueZ fully releases the HCI link, then the next
            # call triggers a clean fresh reconnect.
            _LOGGER.warning(
                "Transaction (evt_type=%d, ctrl=%s) failed on %s, "
                "clearing session: %r",
                evt_type, ctrl, self._device.address, err,
            )
            await self._clear_session()
            raise

        # Check for errors
        errors = _BlancoUnitProtocol.extract_errors(response)
        if errors:
            _LOGGER.debug(
                "Transaction response contains errors: %s", errors
            )
        for error in errors:
            if error.get("err_code") == 4:
                raise BlancoUnitAuthenticationError(
                    "Authentication error during operation"
                )

        return response

    # -------------------------------
    # region Read Operations
    # -------------------------------

    async def get_system_info(self) -> BlancoUnitSystemInfo:
        """Read and return system information (firmware versions, device name, reset count)."""
        resp = await self._execute_transaction(evt_type=7, ctrl=3, pars={"evt_type": 2})
        pars = _BlancoUnitProtocol.extract_pars(resp)
        return BlancoUnitSystemInfo(
            sw_ver_comm_con=pars.get("sw_ver_comm_con", {}).get("val", "Unknown"),
            sw_ver_elec_con=pars.get("sw_ver_elec_con", {}).get("val", "Unknown"),
            sw_ver_main_con=pars.get("sw_ver_main_con", {}).get("val", "Unknown"),
            dev_name=pars.get("dev_name", {}).get("val", "Unknown"),
            reset_cnt=pars.get("reset_cnt", {}).get("val", 0),
        )

    async def get_settings(self) -> BlancoUnitSettings:
        """Read and return device configuration settings."""
        resp = await self._execute_transaction(evt_type=7, ctrl=3, pars={"evt_type": 5})
        pars = _BlancoUnitProtocol.extract_pars(resp)
        return BlancoUnitSettings(
            calib_still_wtr=pars.get("calib_still_wtr", {}).get("val", 0),
            calib_soda_wtr=pars.get("calib_soda_wtr", {}).get("val", 0),
            filter_life_tm=pars.get("filter_life_tm", {}).get("val", 0),
            post_flush_quantity=pars.get("post_flush_quantity", {}).get("val", 0),
            set_point_cooling=pars.get("set_point_cooling", {}).get("val", 0),
            wtr_hardness=pars.get("wtr_hardness", {}).get("val", 0),
            # CHOICE.All specific fields
            set_point_heating=pars.get("set_point_heating", {}).get("val", 0),
            calib_hot_wtr=pars.get("calib_hot_wtr", {}).get("val", 0),
            gbl_medium_wtr_ratio=pars.get("gbl_medium_wtr_ratio", {}).get("val", 0.0),
            gbl_classic_wtr_ratio=pars.get("gbl_classic_wtr_ratio", {}).get("val", 0.0),
        )

    async def get_status(self) -> BlancoUnitStatus:
        """Read and return real-time device status."""
        resp = await self._execute_transaction(evt_type=7, ctrl=3, pars={"evt_type": 6})
        pars = _BlancoUnitProtocol.extract_pars(resp)
        return BlancoUnitStatus(
            tap_state=pars.get("tap_state", {}).get("val", 0),
            filter_rest=pars.get("filter_rest", {}).get("val", 0),
            co2_rest=pars.get("co2_rest", {}).get("val", 0),
            wtr_disp_active=pars.get("wtr_disp_active", {}).get("val", False),
            firm_upd_avlb=pars.get("firm_upd_avlb", {}).get("val", False),
            set_point_cooling=pars.get("set_point_cooling", {}).get("val", 0),
            clean_mode_state=pars.get("clean_mode_state", {}).get("val", 0),
            err_bits=pars.get("err_bits", {}).get("val", 0),
            # CHOICE.All specific fields
            temp_boil_1=pars.get("temp_boil_1", {}).get("val", 0),
            temp_boil_2=pars.get("temp_boil_2", {}).get("val", 0),
            temp_comp=pars.get("temp_comp", {}).get("val", 0),
            main_controller_status=pars.get("main_controller_status", {}).get("val", 0),
            conn_controller_status=pars.get("conn_controller_status", {}).get("val", 0),
        )

    async def get_device_identity(self) -> BlancoUnitIdentity:
        """Read and return device identity (serial number, service code)."""
        resp = await self._execute_transaction(evt_type=7, ctrl=2, pars={})
        pars = _BlancoUnitProtocol.extract_pars(resp)
        return BlancoUnitIdentity(
            serial_no=pars.get("ser_no", "Unknown"),
            service_code=pars.get("serv_code", "Unknown"),
        )

    async def get_wifi_info(self) -> BlancoUnitWifiInfo:
        """Read and return WiFi and network information."""
        resp = await self._execute_transaction(evt_type=7, ctrl=10, pars={})
        pars = _BlancoUnitProtocol.extract_pars(resp)
        return BlancoUnitWifiInfo(
            cloud_connect=pars.get("cloud_connect", {}).get("val", False),
            ssid=pars.get("ssid", {}).get("val", ""),
            signal=pars.get("signal", {}).get("val", 0),
            ip=pars.get("ip", {}).get("val", ""),
            ble_mac=pars.get("b_mac", {}).get("val", ""),
            wifi_mac=pars.get("w_mac", {}).get("val", ""),
            gateway=pars.get("default_gateway", {}).get("val", ""),
            gateway_mac=pars.get("default_gateway_mac", {}).get("val", ""),
            subnet=pars.get("subnet", {}).get("val", ""),
        )

    # -------------------------------
    # region Write Operations
    # -------------------------------

    async def set_temperature(self, cooling_celsius: int) -> bool:
        """Set cooling temperature (4-10°C).

        Args:
            cooling_celsius: Target cooling temperature in Celsius (4-10).

        Returns:
            True if successful.

        Raises:
            ValueError: If temperature is out of range.
        """
        if not (4 <= cooling_celsius <= 10):
            raise ValueError("Temperature must be between 4 and 10°C")

        _LOGGER.info("Setting cooling temperature to %d°C", cooling_celsius)
        req = _SetTemperaturePars(cooling_celsius=cooling_celsius)
        resp = await self._execute_transaction(evt_type=7, ctrl=5, pars=req.to_pars())
        return resp.get("type") == 2

    async def set_heating_temperature(self, heating_celsius: int) -> bool:
        """Set heating/boiling temperature (85-100°C, CHOICE.All only).

        Args:
            heating_celsius: Target heating temperature in Celsius (85-100).

        Returns:
            True if successful.

        Raises:
            ValueError: If temperature is out of range.
        """
        if not (60 <= heating_celsius <= 100):
            raise ValueError("Heating temperature must be between 60 and 100°C")

        _LOGGER.info("Setting heating temperature to %d°C", heating_celsius)
        req = _SetHeatingTemperaturePars(heating_celsius=heating_celsius)
        resp = await self._execute_transaction(evt_type=7, ctrl=5, pars=req.to_pars())
        return resp.get("type") == 2

    async def set_water_hardness(self, level: int) -> bool:
        """Set water hardness level (1-9).

        Args:
            level: Water hardness level (1-9).

        Returns:
            True if successful.

        Raises:
            ValueError: If level is out of range.
        """
        _LOGGER.info("Setting water hardness to level %d", level)
        req = _SetWaterHardnessPars(level=level)
        resp = await self._execute_transaction(evt_type=7, ctrl=5, pars=req.to_pars())
        return resp.get("type") == 2

    async def change_pin(self, new_pin: str) -> bool:
        """Change the device PIN.

        Args:
            new_pin: New 5-digit PIN.

        Returns:
            True if successful.

        Raises:
            ValueError: If PIN format is invalid.
        """
        _LOGGER.info("Changing PIN")
        req = _ChangePinPars(new_pin=new_pin)
        resp = await self._execute_transaction(evt_type=7, ctrl=13, pars=req.to_pars())
        if resp.get("type") == 2:
            self._pin = new_pin
            return True
        return False

    async def dispense_water(self, amount_ml: int, co2_intensity: int) -> bool:
        """Dispense water with specified amount and carbonation.

        Args:
            amount_ml: Amount in milliliters (100-1500, must be multiple of 100).
            co2_intensity: CO2 carbonation level (1=still, 2=medium, 3=high).

        Returns:
            True if dispensing started successfully.

        Raises:
            ValueError: If amount or intensity is invalid.
        """
        if not (100 <= amount_ml <= 1500):
            raise ValueError("Amount must be between 100ml and 1500ml")
        if co2_intensity not in (1, 2, 3):
            raise ValueError("CO2 intensity must be 1 (still), 2 (medium), or 3 (high)")

        _LOGGER.info("Dispensing %dml with CO2 intensity %d", amount_ml, co2_intensity)
        req = _DispensePars(amount_ml=amount_ml, co2_intensity=co2_intensity)
        resp = await self._execute_transaction(
            evt_type=7, ctrl=1000, pars=req.to_pars()
        )
        return resp.get("type") == 2

    async def set_calibration_still(self, amount: int) -> bool:
        """Set calibration amount for still water.

        Args:
            amount: Calibration amount.

        Returns:
            True if successful.
        """
        _LOGGER.info("Setting still water calibration to %d", amount)
        req = _SetCalibrationPars(calib_type="calib_still_wtr", amount=amount)
        resp = await self._execute_transaction(evt_type=7, ctrl=5, pars=req.to_pars())
        return resp.get("type") == 2

    async def set_calibration_soda(self, amount: int) -> bool:
        """Set calibration amount for soda water.

        Args:
            amount: Calibration amount.

        Returns:
            True if successful.
        """
        _LOGGER.info("Setting soda water calibration to %d", amount)
        req = _SetCalibrationPars(calib_type="calib_soda_wtr", amount=amount)
        resp = await self._execute_transaction(evt_type=7, ctrl=5, pars=req.to_pars())
        return resp.get("type") == 2

    # -------------------------------
    # region WiFi & Device Management
    # -------------------------------

    # TODO only allowed if not currently connected else returns ctrl_errs = 5
    async def scan_wifi_networks(self) -> list[BlancoUnitWifiNetwork]:
        """Scan for available WiFi networks.

        Returns:
            List of discovered WiFi access points.
        """
        _LOGGER.info("Scanning for WiFi networks")
        resp = await self._execute_transaction(evt_type=7, ctrl=12, pars={})
        pars = _BlancoUnitProtocol.extract_pars(resp)
        aps = pars.get("aps", [])
        return [
            BlancoUnitWifiNetwork(
                ssid=ap.get("ssid", ""),
                signal=ap.get("signal", 0),
                auth_mode=ap.get("auth_mode", 0),
            )
            for ap in aps
        ]

    async def connect_wifi(self, ssid: str, password: str) -> bool:
        """Connect the device to a WiFi network.

        Args:
            ssid: The WiFi network name.
            password: The WiFi network password.

        Returns:
            True if successful.
        """
        _LOGGER.info("Connecting to WiFi network: %s", ssid)
        req = _ConnectWifiPars(ssid=ssid, password=password)
        resp = await self._execute_transaction(evt_type=7, ctrl=7, pars=req.to_pars())
        return resp.get("type") == 2

    async def disconnect_wifi(self) -> bool:
        """Disconnect the device from WiFi.

        Returns:
            True if successful.
        """
        _LOGGER.info("Disconnecting from WiFi")
        req = _ConnectWifiPars(ssid="", password="")
        resp = await self._execute_transaction(evt_type=7, ctrl=7, pars=req.to_pars())
        return resp.get("type") == 2

    async def allow_cloud_services(self, rca_id: str = "") -> bool:
        """Allow cloud services (Freigabe).

        Args:
            rca_id: Remote cloud access ID (empty string to allow all).

        Returns:
            True if successful.
        """
        _LOGGER.info("Allowing cloud services (rca_id=%s)", rca_id)
        req = _AllowCloudServicesPars(rca_id=rca_id)
        resp = await self._execute_transaction(evt_type=7, ctrl=14, pars=req.to_pars())
        return resp.get("type") == 2

    async def factory_reset(self) -> bool:
        """Perform a full software reset of the device.

        Returns:
            True if successful.
        """
        _LOGGER.info("Performing factory reset")
        resp = await self._execute_transaction(evt_type=7, ctrl=15, pars={})
        return resp.get("type") == 2

    # -------------------------------
    # region Protocol Discovery
    # -------------------------------

    async def test_protocol_parameters(
        self, evt_type: int, ctrl: int | None = None, pars: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Test protocol parameters and return response if it contains meaningful data.

        Args:
            evt_type: Event type to test.
            ctrl: Control parameter to test (optional).
            pars: Parameters dictionary to test (optional).

        Returns:
            Response dictionary if it contains meaningful data, None otherwise.
        """
        try:
            return await self._execute_transaction(
                evt_type=evt_type, ctrl=ctrl, pars=pars
            )
        except BlancoUnitAuthenticationError:
            raise
        except Exception as e:  # noqa: BLE001
            _LOGGER.debug(
                "Test failed for evt_type=%s, ctrl=%s, pars=%s: %s",
                evt_type,
                ctrl,
                pars,
                e,
            )
            return None


# -------------------------------
# region Standalone Functions
# -------------------------------


@dataclass
class PinValidationResult:
    """Result of PIN validation."""

    is_valid: bool
    dev_id: str | None
    dev_type: int | None


def _extract_device_id(response: dict[str, Any]) -> str | None:
    """Extract device ID from a pairing response.

    Args:
        response: The response dictionary from a pairing request.

    Returns:
        The device ID if found, None otherwise.
    """
    try:
        body = response.get("body", {})
        meta = body.get("meta", {})
        if "dev_id" in meta:
            return meta["dev_id"]
    except (KeyError, TypeError):
        pass
    return None


def _extract_device_type(response: dict[str, Any]) -> int | None:
    """Extract device type from a pairing response.

    Args:
        response: The response dictionary from a pairing request.

    Returns:
        The device type if found, None otherwise.
    """
    try:
        body = response.get("body", {})
        meta = body.get("meta", {})
        if "dev_type" in meta:
            return meta["dev_type"]
    except (KeyError, TypeError):
        pass
    return None


async def validate_pin(
    client: BleakClient, pin: str, protocol: _BlancoUnitProtocol | None = None
) -> PinValidationResult:
    """Test if a PIN is valid by attempting to pair with the device.

    This is a standalone function that works with an existing BleakClient.

    Args:
        client: An active BleakClient connection.
        pin: The 5-digit PIN to validate.
        protocol: Optional protocol instance. If None, creates a new one.

    Returns:
        PinValidationResult containing:
            - is_valid: True if PIN is valid, False if wrong PIN (error code 4)
            - response: The full response from the pairing attempt
            - dev_id: The device ID if pairing was successful, None otherwise

    Raises:
        ValueError: If PIN format is invalid.
        TimeoutError: If response chunks cannot be read completely.
        Any other exceptions are propagated (connection errors, etc.)
    """
    if len(pin) != 5 or not pin.isdigit():
        raise ValueError("PIN must be exactly 5 digits")

    _LOGGER.debug("Validating PIN")

    # Use provided protocol or create new one
    if protocol is None:
        protocol = _BlancoUnitProtocol(mtu=MTU_SIZE)

    # Send pairing request and get response
    response = await protocol.send_pairing_request(client, pin)

    dev_id = _extract_device_id(response)
    dev_type = _extract_device_type(response)

    # Check for authentication error (error code 4)
    errors = _BlancoUnitProtocol.extract_errors(response)
    for error in errors:
        if error.get("err_code") == 4:
            _LOGGER.debug("PIN validation failed: wrong PIN (error code 4)")
            return PinValidationResult(is_valid=False, dev_type=dev_type, dev_id=dev_id)

    if dev_id is not None:
        _LOGGER.debug("PIN validation successful, dev_id: %s", dev_id)
        return PinValidationResult(is_valid=True, dev_type=dev_type, dev_id=dev_id)

    _LOGGER.debug("PIN validation failed: no device ID or device type in response")
    return PinValidationResult(is_valid=False, dev_type=dev_type, dev_id=dev_id)


# -------------------------------
# region Session Data
# -------------------------------


@dataclass
class _BlancoUnitSessionData:
    """Internal: Session data stored during connection."""

    client: BleakClient
    dev_id: str
    dev_type: int
    protocol: _BlancoUnitProtocol
