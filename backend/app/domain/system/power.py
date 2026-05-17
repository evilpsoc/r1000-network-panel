from fastapi import HTTPException

from app.core.host import host_command_available, run_command_full


def restart_host() -> dict[str, object]:
    if host_command_available("/usr/sbin/shutdown"):
        cmd = ["chroot", "/host", "/usr/sbin/shutdown", "-r", "now"]
    elif host_command_available("/usr/sbin/reboot"):
        cmd = ["chroot", "/host", "/usr/sbin/reboot"]
    else:
        raise HTTPException(status_code=500, detail="Host restart command not available")
    code, stdout, stderr = run_command_full(cmd)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Restart command failed"},
        )
    return {"ok": True, "stdout": stdout, "stderr": stderr}


def poweroff_host() -> dict[str, object]:
    if host_command_available("/usr/sbin/shutdown"):
        cmd = ["chroot", "/host", "/usr/sbin/shutdown", "-P", "now"]
    elif host_command_available("/usr/sbin/poweroff"):
        cmd = ["chroot", "/host", "/usr/sbin/poweroff"]
    else:
        raise HTTPException(status_code=500, detail="Host poweroff command not available")
    code, stdout, stderr = run_command_full(cmd)
    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": code, "stdout": stdout, "stderr": stderr or "Power off command failed"},
        )
    return {"ok": True, "stdout": stdout, "stderr": stderr}
