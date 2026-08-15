"""BlueZ D-Bus helpers for Blanco Unit BLE device pairing."""

# NOTE: Do NOT add `from __future__ import annotations` to this module.
# The PasskeyAgent below is a dbus_fast ServiceInterface whose @method
# decorators read the D-Bus type-code annotations (e.g. "o", "u", "q")
# literally at class-definition time. Deferred (PEP 563) annotations make
# dbus_fast resolve the `-> None` returns to NoneType, which crashes the
# decorator with: TypeError: Argument 'signature' ... expected str, got
# NoneType — breaking BLE pairing in the config flow.

import asyncio
import logging
import sys
from typing import Any

_LOGGER = logging.getLogger(__name__)


async def _find_bluez_device_path(bus: Any, address: str) -> str | None:
    """Find the BlueZ D-Bus object path for a BLE device by address."""
    # Try the conventional path (hci0) first
    default_path = "/org/bluez/hci0/dev_" + address.upper().replace(":", "_")
    try:
        await bus.introspect("org.bluez", default_path)
        return default_path
    except Exception:
        pass

    # Fall back to searching the object tree (handles non-hci0 adapters)
    try:
        introspection = await bus.introspect("org.bluez", "/")
        root = bus.get_proxy_object("org.bluez", "/", introspection)
        obj_manager = root.get_interface("org.freedesktop.DBus.ObjectManager")
        objects = await obj_manager.call_get_managed_objects()

        addr_upper = address.upper()
        for path, interfaces in objects.items():
            if "org.bluez.Device1" in interfaces:
                device_props = interfaces["org.bluez.Device1"]
                addr_variant = device_props.get("Address")
                if addr_variant and addr_variant.value.upper() == addr_upper:
                    return path
    except Exception:
        _LOGGER.debug("Failed to search BlueZ object tree", exc_info=True)

    return None


async def async_is_device_bonded(address: str) -> bool:
    """Check whether a BLE device is already bonded in BlueZ."""
    if sys.platform != "linux":
        return False

    try:
        from dbus_fast import BusType  # noqa: PLC0415
        from dbus_fast.aio import MessageBus  # noqa: PLC0415

        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        try:
            dev_path = await _find_bluez_device_path(bus, address)
            if dev_path is None:
                return False
            introspection = await bus.introspect("org.bluez", dev_path)
            proxy = bus.get_proxy_object("org.bluez", dev_path, introspection)
            props = proxy.get_interface("org.freedesktop.DBus.Properties")
            paired = await props.call_get("org.bluez.Device1", "Paired")
            return bool(paired.value)
        finally:
            bus.disconnect()
    except Exception:
        _LOGGER.debug("Could not check bonding status via D-Bus", exc_info=True)
        return False


async def async_remove_bluez_device(address: str) -> bool:
    """Remove a BLE device from BlueZ to clear stale GATT cache and bonding keys."""
    if sys.platform != "linux":
        return False

    try:
        from dbus_fast import BusType  # noqa: PLC0415
        from dbus_fast.aio import MessageBus  # noqa: PLC0415

        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        try:
            dev_path = await _find_bluez_device_path(bus, address)
            if dev_path is None:
                _LOGGER.debug(
                    "Device %s not found in BlueZ, nothing to remove", address
                )
                return True

            adapter_path = "/".join(dev_path.split("/")[:-1])
            adapter_intro = await bus.introspect("org.bluez", adapter_path)
            adapter_proxy = bus.get_proxy_object(
                "org.bluez", adapter_path, adapter_intro
            )
            adapter1 = adapter_proxy.get_interface("org.bluez.Adapter1")
            await adapter1.call_remove_device(dev_path)
            _LOGGER.info("Removed device %s from BlueZ", address)
            return True
        finally:
            bus.disconnect()
    except Exception:
        _LOGGER.warning(
            "Failed to remove device %s from BlueZ", address, exc_info=True
        )
        return False


async def async_pair_bluez_device(address: str, passkey: str) -> bool:
    """Pair with a BLE device via BlueZ D-Bus using a numeric passkey.

    Flow:
    1. Remove device from BlueZ (clear stale GATT cache)
    2. Wait for device to reappear via BLE advertising
    3. Pair with the passkey agent
    4. Trust + disconnect so bleak can connect cleanly
    """
    if sys.platform != "linux":
        _LOGGER.error("BlueZ D-Bus pairing is only available on Linux")
        return False

    from dbus_fast import BusType, Variant  # noqa: PLC0415
    from dbus_fast.aio import MessageBus  # noqa: PLC0415
    from dbus_fast.service import ServiceInterface, method  # noqa: PLC0415

    passkey_int = int(passkey)
    agent_path = f"/org/bluez/agent_blanco_{id(address)}"

    _LOGGER.info("Starting BlueZ pairing for %s", address)

    class PasskeyAgent(ServiceInterface):
        """BlueZ Agent1 that supplies a fixed numeric passkey."""

        def __init__(self, pk: int) -> None:
            super().__init__("org.bluez.Agent1")
            self._pk = pk

        @method()
        def Release(self) -> None:  # noqa: N802
            pass

        @method()
        def RequestPasskey(self, device: "o") -> "u":  # type: ignore[override]  # noqa: F821, N802
            _LOGGER.debug("BlueZ agent: providing passkey for %s", device)
            return self._pk

        @method()
        def DisplayPasskey(self, device: "o", passkey: "u", entered: "q") -> None:  # noqa: F821, N802
            pass

        @method()
        def RequestConfirmation(self, device: "o", passkey: "u") -> None:  # noqa: F821, N802
            pass

        @method()
        def AuthorizeService(self, device: "o", uuid: "s") -> None:  # noqa: F821, N802
            pass

        @method()
        def Cancel(self) -> None:  # noqa: N802
            pass

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        # Register the passkey agent
        agent = PasskeyAgent(passkey_int)
        bus.export(agent_path, agent)

        mgr_introspection = await bus.introspect("org.bluez", "/org/bluez")
        mgr_proxy = bus.get_proxy_object(
            "org.bluez", "/org/bluez", mgr_introspection
        )
        agent_manager = mgr_proxy.get_interface("org.bluez.AgentManager1")
        await agent_manager.call_register_agent(agent_path, "KeyboardDisplay")
        _LOGGER.debug("BlueZ passkey agent registered at %s", agent_path)

        try:
            # Step 1: Remove device to clear stale GATT cache
            dev_path = await _find_bluez_device_path(bus, address)
            if dev_path is not None:
                adapter_path = "/".join(dev_path.split("/")[:-1])
                _LOGGER.debug(
                    "Removing device %s to clear stale GATT cache", dev_path
                )
                try:
                    adapter_intro = await bus.introspect(
                        "org.bluez", adapter_path
                    )
                    adapter_proxy = bus.get_proxy_object(
                        "org.bluez", adapter_path, adapter_intro
                    )
                    adapter1 = adapter_proxy.get_interface("org.bluez.Adapter1")
                    await adapter1.call_remove_device(dev_path)
                    _LOGGER.debug("Device removed successfully")
                except Exception:
                    _LOGGER.debug(
                        "RemoveDevice failed (non-fatal)", exc_info=True
                    )
                await asyncio.sleep(2)

            # Step 2: Wait for device to reappear via BLE advertising
            _LOGGER.debug("Waiting for device %s to reappear...", address)
            dev_path = None
            for _ in range(30):  # up to 30s
                dev_path = await _find_bluez_device_path(bus, address)
                if dev_path is not None:
                    break
                await asyncio.sleep(1)

            if dev_path is None:
                _LOGGER.error(
                    "Device %s did not reappear after removal (timeout)",
                    address,
                )
                return False
            _LOGGER.debug("Device reappeared at %s", dev_path)

            # Step 3: Pair (fresh GATT discovery, no stale cache)
            dev_introspection = await bus.introspect("org.bluez", dev_path)
            dev_proxy = bus.get_proxy_object(
                "org.bluez", dev_path, dev_introspection
            )
            device1 = dev_proxy.get_interface("org.bluez.Device1")

            await asyncio.wait_for(device1.call_pair(), timeout=30.0)
            _LOGGER.info("BlueZ pairing successful for %s", address)

            # Step 4: Trust + disconnect so bleak can connect cleanly
            props = dev_proxy.get_interface(
                "org.freedesktop.DBus.Properties"
            )
            await props.call_set(
                "org.bluez.Device1", "Trusted", Variant("b", True)
            )
            try:
                await device1.call_disconnect()
                _LOGGER.debug("Disconnected after pairing")
            except Exception:
                _LOGGER.debug(
                    "Disconnect after pair failed (non-fatal)", exc_info=True
                )
            await asyncio.sleep(2)

            return True
        finally:
            try:
                await agent_manager.call_unregister_agent(agent_path)
            except Exception:
                pass
    except Exception:
        _LOGGER.exception("BlueZ D-Bus pairing failed for %s", address)
        return False
    finally:
        bus.disconnect()


async def async_ensure_bonded(address: str, passkey: str) -> bool:
    """Ensure a BLE device is bonded in BlueZ. If not, pair it.

    Returns True if the device is bonded (either already was, or newly paired).
    """
    if sys.platform != "linux":
        _LOGGER.debug("Not on Linux, skipping bonding check")
        return True

    try:
        is_bonded = await async_is_device_bonded(address)
        if is_bonded:
            _LOGGER.debug("Device %s is already bonded", address)
            return True

        _LOGGER.info(
            "Device %s is not bonded, initiating pairing with passkey",
            address,
        )
        return await async_pair_bluez_device(address, passkey)
    except Exception:
        _LOGGER.exception("Failed to ensure bonding for %s", address)
        return False
