import json

from app.core.host import run_command_full


def get_filesystem_status() -> dict[str, object]:
    disks_code, disks_out, _ = run_command_full(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,MODEL,TRAN,HOTPLUG,RM"])
    mounts_code, mounts_out, _ = run_command_full(["df", "-hP"])
    disks = []
    if disks_code == 0 and disks_out:
        try:
            disks = json.loads(disks_out).get("blockdevices", [])
        except Exception:
            disks = []

    mounts = []
    if mounts_code == 0 and mounts_out:
        for line in mounts_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            mounts.append(
                {
                    "filesystem": parts[0],
                    "size": parts[1],
                    "used": parts[2],
                    "available": parts[3],
                    "use_percent": parts[4],
                    "mountpoint": parts[5],
                }
            )
    external = []

    def walk_disk(entries: list[dict[str, object]]) -> None:
        for entry in entries:
            if str(entry.get("tran", "")).lower() == "usb" or bool(entry.get("hotplug")) or bool(entry.get("rm")):
                external.append(entry)
            children = entry.get("children", [])
            if isinstance(children, list):
                walk_disk(children)

    walk_disk(disks)
    return {"disks": disks, "mounts": mounts, "external": external}
