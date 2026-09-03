import subprocess
def _run_cmd(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        return r.returncode, out or err
    except Exception as e:
        return -1, str(e)
print(_run_cmd(["sudo", "-n", "systemctl", "disable", "watch_manager_ip.timer", "--now"]))
