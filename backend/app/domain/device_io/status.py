import os
import re
import socket
import time
from pathlib import Path

from app.core.host import command_exists, read_text, run_command_full
from app.domain.system.sessions import get_active_sessions


DEVICE_IO_LED_POLICY = {
    "last_blue_blink": 0.0,
    "last_user_state": "",
    "last_act_trigger": "",
    "manual_override_until": 0.0,
    "manual_user_override_until": 0.0,
    "manual_act_override_until": 0.0,
    "last_disk_activity_total": 0,
    "last_act_pulse": 0.0,
    "online": False,
    "internet_success_count": 0,
    "internet_failure_count": 0,
}
DEVICE_IO_LED_POLICY_ENABLED = os.getenv("DEVICE_IO_LED_POLICY_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
DEVICE_IO_ACT_SOFTWARE_DISK_LED = os.getenv("DEVICE_IO_ACT_SOFTWARE_DISK_LED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
DEVICE_IO_INTERNET_DOWN_FAILURES = int(os.getenv("DEVICE_IO_INTERNET_DOWN_FAILURES", "4") or "4")
DEVICE_IO_LED_POLICY_INTERVAL_SECONDS = float(os.getenv("DEVICE_IO_LED_POLICY_INTERVAL_SECONDS", "15") or "15")
DEVICE_IO_ACT_DISK_POLL_SECONDS = float(os.getenv("DEVICE_IO_ACT_DISK_POLL_SECONDS", "0.5") or "0.5")
DEVICE_IO_ACT_DISK_NAMES = tuple(
    name.strip()
    for name in os.getenv("DEVICE_IO_ACT_DISK_NAMES", "nvme0n1,mmcblk0,sda,sdb").split(",")
    if name.strip()
)
DEVICE_IO_LED_ROLE_ALIASES = {
    "act": ("act", "activity", "disk-activity", "storage", "mmc0"),
    "red": ("led-red", "usrred", "userred", "user-red", "usr-r", "red-led"),
    "green": ("led-green", "usrgreen", "usergreen", "user-green", "usr-g", "green-led"),
    "blue": ("led-blue", "usrblue", "userblue", "user-blue", "usr-b", "blue-led"),
}
DEVICE_IO_ACT_TRIGGERS = ("disk-activity", "mmc0", "activity")
DEVICE_IO_ACTIVE_LOW_LED_ROLES = {
    role.strip().lower()
    for role in os.getenv("DEVICE_IO_ACTIVE_LOW_LED_ROLES", "").split(",")
    if role.strip()
}


class DeviceIoError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def read_text_raw(path: Path, default: str = "") -> str:
    try:
        return path.read_text().strip()
    except Exception:
        return default


def led_sysfs_roots() -> list[Path]:
    roots = [Path("/host-sys/class/leds"), Path("/sys/class/leds"), Path("/host/sys/class/leds")]
    return [root for root in roots if root.exists()]


def parse_led_trigger(raw: str) -> tuple[str, list[str]]:
    current = ""
    available = []
    for token in raw.split():
        if token.startswith("[") and token.endswith("]"):
            current = token[1:-1]
            available.append(current)
        else:
            available.append(token)
    return current, available


def get_led_status() -> list[dict[str, object]]:
    leds: dict[str, dict[str, object]] = {}
    for root in led_sysfs_roots():
        for entry in sorted(root.iterdir(), key=lambda item: item.name):
            if not entry.exists():
                continue
            name = entry.name
            trigger_raw = read_text_raw(entry / "trigger")
            current_trigger, triggers = parse_led_trigger(trigger_raw)
            brightness_path = entry / "brightness"
            trigger_path = entry / "trigger"
            role = led_role_name(name)
            leds.setdefault(name, {
                "name": name,
                "role": role,
                "source": str(root),
                "brightness": read_text_raw(brightness_path, "unknown"),
                "max_brightness": read_text_raw(entry / "max_brightness", "unknown"),
                "trigger": current_trigger or read_text_raw(trigger_path, "unknown"),
                "triggers": triggers,
                "active_low": led_is_active_low(name),
                "logical_on_brightness": led_logical_on_value(name),
                "logical_off_brightness": led_logical_off_value(name),
                "can_set_brightness": os.access(brightness_path, os.W_OK) and not protected_led_name(name),
                "can_set_trigger": os.access(trigger_path, os.W_OK) and not protected_led_name(name),
                "protected": protected_led_name(name),
            })
    return list(leds.values())


def get_serial_status() -> list[dict[str, str]]:
    ports: dict[str, dict[str, str]] = {}
    patterns = [
        "/dev/ttyS*",
        "/dev/ttyAMA*",
        "/dev/ttyUSB*",
        "/host/dev/ttyS*",
        "/host/dev/ttyAMA*",
        "/host/dev/ttyUSB*",
    ]
    for pattern in patterns:
        for path in sorted(Path(pattern).parent.glob(Path(pattern).name)):
            display_path = str(path).replace("/host", "", 1)
            if display_path in ports:
                continue
            ports[display_path] = {
                "path": display_path,
                "source": str(path),
                "kind": "usb-modem" if "ttyUSB" in path.name else ("uart" if "ttyAMA" in path.name else "serial"),
                "readable": "yes" if os.access(path, os.R_OK) else "no",
                "writable": "yes" if os.access(path, os.W_OK) else "no",
                "link": "",
            }

    for symlink_root in (Path("/dev/serial"), Path("/host/dev/serial")):
        if not symlink_root.exists():
            continue
        for link in sorted(symlink_root.rglob("*")):
            if not link.is_symlink():
                continue
            try:
                target = str(link.resolve()).replace("/host", "", 1)
            except Exception:
                target = ""
            if target in ports:
                ports[target]["link"] = str(link).replace("/host", "", 1)
    return sorted(ports.values(), key=lambda item: item["path"])


def get_gpio_status() -> list[dict[str, str]]:
    chips = []
    for root in (Path("/sys/class/gpio"), Path("/host/sys/class/gpio")):
        if not root.exists():
            continue
        for chip in sorted(root.glob("gpiochip*"), key=lambda item: item.name):
            chips.append(
                {
                    "name": chip.name,
                    "source": str(chip),
                    "label": read_text_raw(chip / "label", ""),
                    "base": read_text_raw(chip / "base", ""),
                    "ngpio": read_text_raw(chip / "ngpio", ""),
                }
            )
    unique = {}
    for chip in chips:
        unique.setdefault(chip["name"], chip)
    return list(unique.values())


def writable_led_path(name: str) -> Path | None:
    if not re.fullmatch(r"[A-Za-z0-9_.:+-]+", name or ""):
        return None
    for root in (Path("/host-sys/class/leds"), Path("/sys/class/leds")):
        led = root / name
        if led.exists():
            return led
    return None


def led_name_matches(name: str, aliases: tuple[str, ...]) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "", name.lower())
    return any(re.sub(r"[^a-z0-9]+", "", alias.lower()) in normalized for alias in aliases)


def led_role_name(name: str) -> str:
    if led_name_matches(name, DEVICE_IO_LED_ROLE_ALIASES["act"]):
        return "act"
    if led_name_matches(name, DEVICE_IO_LED_ROLE_ALIASES["red"]):
        return "red"
    if led_name_matches(name, DEVICE_IO_LED_ROLE_ALIASES["green"]):
        return "green"
    if led_name_matches(name, DEVICE_IO_LED_ROLE_ALIASES["blue"]):
        return "blue"
    return ""


def protected_led_name(name: str) -> bool:
    return name.upper() == "PWR"


def find_led_name(aliases: tuple[str, ...]) -> str:
    for led in get_led_status():
        name = str(led.get("name", ""))
        if led_name_matches(name, aliases):
            return name
    return ""


def user_rgb_led_names() -> dict[str, str]:
    leds = {str(led.get("name", "")): led for led in get_led_status()}
    expected = {"red": "led-red", "green": "led-green", "blue": "led-blue"}
    if all(name in leds for name in expected.values()):
        return expected
    return {
        "red": find_led_name(("led-red", "userred", "usrred", "userr", "usr:r", "usr-r", "user-red")),
        "green": find_led_name(("led-green", "usergreen", "usrgreen", "userg", "usr:g", "usr-g", "user-green")),
        "blue": find_led_name(("led-blue", "userblue", "usrblue", "userb", "usr:b", "usr-b", "user-blue")),
    }


def act_led_name() -> str:
    return find_led_name(DEVICE_IO_LED_ROLE_ALIASES["act"])


def set_led_trigger(name: str, preferred_triggers: tuple[str, ...]) -> str:
    led = writable_led_path(name)
    if not led:
        return ""
    trigger_path = led / "trigger"
    current, available = parse_led_trigger(read_text_raw(trigger_path))
    for trigger in preferred_triggers:
        if trigger in available:
            if current != trigger:
                try:
                    trigger_path.write_text(trigger)
                except Exception:
                    pass
            return trigger
    return current


def configure_timer_led(name: str, delay_on_ms: int = 125, delay_off_ms: int = 875) -> bool:
    led = writable_led_path(name)
    if not led:
        return False
    trigger = set_led_trigger(name, ("timer",))
    if trigger != "timer":
        return False
    for field, value in (("delay_on", str(delay_on_ms)), ("delay_off", str(delay_off_ms))):
        path = led / field
        if path.exists():
            try:
                path.write_text(value)
            except Exception:
                pass
    return True


def write_led_value(name: str, field: str, value: str) -> bool:
    led = writable_led_path(name)
    if not led:
        return False
    try:
        (led / field).write_text(value)
        return True
    except Exception:
        return False


def led_is_active_low(name: str) -> bool:
    return led_role_name(name) in DEVICE_IO_ACTIVE_LOW_LED_ROLES


def led_max_write_value(name: str) -> str:
    led = writable_led_path(name)
    if not led:
        return "1"
    max_value = read_text_raw(led / "max_brightness", "1")
    return max_value if max_value.isdigit() else "1"


def led_logical_on_value(name: str) -> str:
    return "0" if led_is_active_low(name) else led_max_write_value(name)


def led_logical_off_value(name: str) -> str:
    return led_max_write_value(name) if led_is_active_low(name) else "0"


def set_led_off(name: str) -> bool:
    if not name:
        return False
    write_led_value(name, "trigger", "none")
    return write_led_value(name, "brightness", led_logical_off_value(name))


def set_led_on(name: str) -> bool:
    if not name:
        return False
    write_led_value(name, "trigger", "none")
    return write_led_value(name, "brightness", led_logical_on_value(name))


def set_user_rgb(red: bool, green: bool, blue: bool) -> dict[str, str]:
    channels = user_rgb_led_names()
    desired = {"red": red, "green": green, "blue": blue}
    for color, led_name in channels.items():
        if not led_name:
            continue
        if desired[color]:
            set_led_on(led_name)
        else:
            set_led_off(led_name)
    return channels


def device_io_manual_override_active() -> bool:
    return device_io_user_override_active() or device_io_act_override_active()


def device_io_user_override_active() -> bool:
    return time.time() < float(DEVICE_IO_LED_POLICY.get("manual_user_override_until", 0.0) or 0.0)


def device_io_act_override_active() -> bool:
    return time.time() < float(DEVICE_IO_LED_POLICY.get("manual_act_override_until", 0.0) or 0.0)


def internet_reachable() -> bool:
    if command_exists("ping"):
        probes = [
            ["ping", "-4", "-c", "1", "-W", "1", "1.1.1.1"],
            ["ping", "-4", "-c", "1", "-W", "1", "8.8.8.8"],
            ["ping", "-6", "-c", "1", "-W", "1", "2606:4700:4700::1111"],
        ]
        for probe in probes:
            code, _, _ = run_command_full(probe)
            if code == 0:
                return True
    tcp_probes = [
        (socket.AF_INET, ("1.1.1.1", 443)),
        (socket.AF_INET, ("8.8.8.8", 443)),
        (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0)),
    ]
    for family, address in tcp_probes:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.5)
                sock.connect(address)
                return True
        except OSError:
            continue
    return False


def stable_internet_reachable() -> bool:
    reachable = internet_reachable()
    if reachable:
        DEVICE_IO_LED_POLICY["internet_success_count"] = int(DEVICE_IO_LED_POLICY.get("internet_success_count", 0) or 0) + 1
        DEVICE_IO_LED_POLICY["internet_failure_count"] = 0
        DEVICE_IO_LED_POLICY["online"] = True
        return True

    DEVICE_IO_LED_POLICY["internet_success_count"] = 0
    failures = int(DEVICE_IO_LED_POLICY.get("internet_failure_count", 0) or 0) + 1
    DEVICE_IO_LED_POLICY["internet_failure_count"] = failures
    if failures >= max(1, DEVICE_IO_INTERNET_DOWN_FAILURES):
        DEVICE_IO_LED_POLICY["online"] = False
    return bool(DEVICE_IO_LED_POLICY.get("online", False))


def has_external_active_session() -> bool:
    return bool(get_active_sessions())


def disk_activity_total() -> int:
    raw = read_text("/proc/diskstats", "")
    total = 0
    wanted = set(DEVICE_IO_ACT_DISK_NAMES)
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 14:
            continue
        name = parts[2]
        if wanted and name not in wanted:
            continue
        try:
            reads_completed = int(parts[3])
            sectors_read = int(parts[5])
            writes_completed = int(parts[7])
            sectors_written = int(parts[9])
            discards_completed = int(parts[14]) if len(parts) > 14 else 0
            sectors_discarded = int(parts[16]) if len(parts) > 16 else 0
        except ValueError:
            continue
        total += reads_completed + sectors_read + writes_completed + sectors_written + discards_completed + sectors_discarded
    return total


def device_act_disk_activity_loop() -> None:
    time.sleep(3)
    act_name = act_led_name()
    if not act_name:
        return
    last_total = disk_activity_total()
    DEVICE_IO_LED_POLICY["last_disk_activity_total"] = last_total
    while True:
        try:
            if DEVICE_IO_ACT_SOFTWARE_DISK_LED and not device_io_act_override_active():
                current_total = disk_activity_total()
                if current_total and current_total != last_total:
                    write_led_value(act_name, "trigger", "none")
                    write_led_value(act_name, "brightness", led_max_write_value(act_name))
                    DEVICE_IO_LED_POLICY["last_act_trigger"] = "software-disk-activity"
                    DEVICE_IO_LED_POLICY["last_act_pulse"] = time.time()
                    time.sleep(0.08)
                    write_led_value(act_name, "brightness", "0")
                last_total = current_total
                DEVICE_IO_LED_POLICY["last_disk_activity_total"] = last_total
            time.sleep(max(0.15, DEVICE_IO_ACT_DISK_POLL_SECONDS))
        except Exception:
            time.sleep(1)


def apply_device_led_policy_once() -> dict[str, object]:
    act_name = act_led_name()
    act_trigger = ""
    if act_name and DEVICE_IO_ACT_SOFTWARE_DISK_LED and not device_io_act_override_active():
        act_trigger = "software-disk-activity"
        DEVICE_IO_LED_POLICY["last_act_trigger"] = act_trigger
    elif act_name and not device_io_act_override_active():
        act_trigger = set_led_trigger(act_name, DEVICE_IO_ACT_TRIGGERS)
    else:
        DEVICE_IO_LED_POLICY["last_act_trigger"] = ""
    if act_trigger:
        DEVICE_IO_LED_POLICY["last_act_trigger"] = act_trigger

    channels = user_rgb_led_names()
    if not all(channels.values()):
        DEVICE_IO_LED_POLICY["last_user_state"] = "waiting-for-led-red-green-blue"
        return {
            "online": False,
            "external_session": False,
            "state": DEVICE_IO_LED_POLICY["last_user_state"],
            "act": DEVICE_IO_LED_POLICY["last_act_trigger"],
            "user_channels": channels,
            "device_policy_enabled": DEVICE_IO_LED_POLICY_ENABLED,
            "manual_override_active": device_io_manual_override_active(),
        }

    if not DEVICE_IO_LED_POLICY_ENABLED:
        DEVICE_IO_LED_POLICY["last_user_state"] = "policy-disabled"
        return {
            "online": stable_internet_reachable(),
            "external_session": has_external_active_session(),
            "state": DEVICE_IO_LED_POLICY["last_user_state"],
            "act": DEVICE_IO_LED_POLICY["last_act_trigger"],
            "user_channels": channels,
            "device_policy_enabled": False,
            "manual_override_active": device_io_manual_override_active(),
        }

    online = stable_internet_reachable()
    external_session = has_external_active_session()
    state = "green-online" if online else "red-offline"
    manual_override = device_io_user_override_active()
    if not manual_override:
        set_user_rgb(not online, online, False)

        if external_session:
            blue_name = channels.get("blue", "")
            state = f"{state}+blue"
            if blue_name and configure_timer_led(blue_name, 125, 875):
                DEVICE_IO_LED_POLICY["last_blue_blink"] = time.time()
            else:
                now = time.time()
                if now - DEVICE_IO_LED_POLICY["last_blue_blink"] >= 3:
                    DEVICE_IO_LED_POLICY["last_blue_blink"] = now
                    set_user_rgb(not online, online, True)
                    time.sleep(0.25)
                    set_user_rgb(not online, online, False)
    else:
        state = f"{state}+manual"

    DEVICE_IO_LED_POLICY["last_user_state"] = state
    return {
        "online": online,
        "external_session": external_session,
        "state": state,
        "act": DEVICE_IO_LED_POLICY["last_act_trigger"],
        "user_channels": channels,
        "device_policy_enabled": True,
        "manual_override_active": device_io_manual_override_active(),
        "manual_user_override_active": device_io_user_override_active(),
        "manual_act_override_active": device_io_act_override_active(),
        "device_policy_note": "ACT uses disk-activity trigger when exposed; USER LEDs map to red/green/blue roles.",
    }


def device_led_policy_loop() -> None:
    time.sleep(12)
    while True:
        try:
            apply_device_led_policy_once()
        except Exception:
            pass
        time.sleep(max(2, DEVICE_IO_LED_POLICY_INTERVAL_SECONDS) if DEVICE_IO_LED_POLICY_ENABLED else 30)


def get_device_io_status() -> dict[str, object]:
    leds = get_led_status()
    serial = get_serial_status()
    gpio = get_gpio_status()
    expected_rs485 = ["/dev/ttyAMA2", "/dev/ttyAMA3", "/dev/ttyAMA5"]
    present_paths = {port["path"] for port in serial}
    notes = []
    missing_rs485 = [path for path in expected_rs485 if path not in present_paths]
    if missing_rs485:
        notes.append("Expected R1000 RS485 UARTs are not visible yet: " + ", ".join(missing_rs485))
    if not any(led.get("role") in {"red", "green", "blue"} for led in leds):
        notes.append("R1000 USER RGB LEDs are not exposed. Expected /sys/class/leds/led-red, led-green and led-blue.")
    if not any(led.get("role") == "act" for led in leds):
        notes.append("ACT LED is not exposed. It should be the storage-activity LED.")
    return {
        "leds": leds,
        "serial_ports": serial,
        "gpio_chips": gpio,
        "expected_rs485": expected_rs485,
        "led_policy": dict(DEVICE_IO_LED_POLICY),
        "device_policy_enabled": DEVICE_IO_LED_POLICY_ENABLED,
        "manual_override_active": device_io_manual_override_active(),
        "notes": notes,
    }


def resolve_writable_led(name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.:+-]+", name or ""):
        raise DeviceIoError(400, "Invalid LED name")
    if protected_led_name(name):
        raise DeviceIoError(400, "PWR LED is reserved for power state")
    led = writable_led_path(name)
    if not led:
        raise DeviceIoError(404, "LED is not available through writable sysfs")
    return led


def update_led(payload: dict) -> dict[str, object]:
    name = str(payload.get("name", "")).strip()
    led = resolve_writable_led(name)
    stdout_parts = []
    trigger = str(payload.get("trigger", "")).strip()
    brightness = str(payload.get("brightness", "")).strip()
    state = str(payload.get("state", "")).strip().lower()
    role = led_role_name(name)

    if trigger:
        trigger_path = led / "trigger"
        _current, available = parse_led_trigger(read_text_raw(trigger_path))
        if available and trigger not in available:
            raise DeviceIoError(400, "Unsupported LED trigger")
        try:
            trigger_path.write_text(trigger)
            stdout_parts.append(f"{name} trigger set to {trigger}")
        except Exception as exc:
            raise DeviceIoError(500, str(exc)) from exc

    if state:
        if state not in {"on", "off"}:
            raise DeviceIoError(400, "State must be on or off")
        brightness = led_logical_on_value(name) if state == "on" else led_logical_off_value(name)

    if brightness:
        if not brightness.isdigit():
            raise DeviceIoError(400, "Brightness must be numeric")
        max_value = read_text_raw(led / "max_brightness", "1")
        try:
            value = int(brightness)
            max_int = int(max_value)
        except ValueError as exc:
            raise DeviceIoError(400, "Invalid brightness range") from exc
        if value < 0 or value > max_int:
            raise DeviceIoError(400, f"Brightness must be between 0 and {max_int}")
        try:
            if not trigger:
                trigger_path = led / "trigger"
                current, available = parse_led_trigger(read_text_raw(trigger_path))
                if "none" in available and current != "none":
                    trigger_path.write_text("none")
                    stdout_parts.append(f"{name} trigger set to none")
            (led / "brightness").write_text(str(value))
            stdout_parts.append(f"{name} brightness set to {value}")
        except Exception as exc:
            raise DeviceIoError(500, str(exc)) from exc

    if role and (brightness or trigger):
        until = time.time() + 600
        if role == "act":
            DEVICE_IO_LED_POLICY["manual_act_override_until"] = until
        if role in {"red", "green", "blue"}:
            DEVICE_IO_LED_POLICY["manual_user_override_until"] = until
            DEVICE_IO_LED_POLICY["last_user_state"] = "manual-override"
        DEVICE_IO_LED_POLICY["manual_override_until"] = max(
            float(DEVICE_IO_LED_POLICY.get("manual_user_override_until", 0.0) or 0.0),
            float(DEVICE_IO_LED_POLICY.get("manual_act_override_until", 0.0) or 0.0),
        )

    return {"ok": True, "stdout": "\n".join(stdout_parts), "status": get_device_io_status()}
