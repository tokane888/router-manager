import os
import re
import shutil
import socket
import subprocess
from datetime import datetime
from typing import Optional

import dns.resolver  # type: ignore
from fastapi import APIRouter, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

app = FastAPI()
router = APIRouter(prefix="/v1")

DNSMASQ_HOSTS_FILE = "/etc/dnsmasq.hosts"
DNSMASQ_D_FILE = "/etc/dnsmasq.d/dnsmasq.hosts"

SSH_BOOT_RESERVATION_FILE = "/var/lib/router-manager/ssh_boot_reservation"
SSH_BOOT_RESERVATION_DIR = "/var/lib/router-manager/"


def is_iptables_rule_exist(ip: str) -> bool:
    result = subprocess.run(
        ["iptables", "-C", "FORWARD", "-d", ip, "-j", "DROP"],
        capture_output=True,
    )
    return result.returncode == 0


def block_domain(domain: str) -> Optional[str]:
    if os.path.exists(DNSMASQ_HOSTS_FILE):
        with open(DNSMASQ_HOSTS_FILE) as file:
            pattern = r"/([^/]+)/"
            lines = file.readlines()
            for line in lines:
                match = re.search(pattern, line)
                if match is None:
                    return (
                        f"failed to parse dnsmasq setting file({DNSMASQ_HOSTS_FILE})."
                    )
                line_domain = match.group(1)
                if line_domain == domain:
                    # block済み
                    return None

    with open(DNSMASQ_HOSTS_FILE, "a") as file:
        file.write(f"address=/{domain}/\n")
        print(f"added {domain} to block list")

    shutil.copy(DNSMASQ_HOSTS_FILE, DNSMASQ_D_FILE)

    subprocess.run(["systemctl", "restart", "dnsmasq"], check=True)

    return None


def block_ip(domain: str) -> Optional[str]:
    source_file = "/etc/iptables/rules.v4"
    backup_dir = os.path.expanduser("~/.backup")
    date_str = datetime.now().strftime("%Y-%m-%d")
    backup_file = os.path.join(backup_dir, f"rules_{date_str}.v4")

    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    shutil.copy2(source_file, backup_file)
    print(f"{source_file} backup.")

    try:
        # ドメインに関連するすべてのIPアドレスを取得
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]
        answer = resolver.resolve(domain)
        ip_addresses = [ip.to_text() for ip in answer]
        blocked_ips = []

        for ip in ip_addresses:
            if is_iptables_rule_exist(ip):
                # ブロック済みIP
                continue
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP"],
                check=True,
            )
            blocked_ips.append(ip)

        # iptablesルールを保存
        subprocess.run(
            ["iptables-save", ">", "/etc/iptables/rules.v4"], shell=True, check=True
        )
        print(f"ip block rule added: {ip_addresses}")

        return None

    except socket.gaierror:
        # 名前解決失敗
        return f"Failed to resolve IP for {domain}."


@router.put("/block/domain/{domain}")
async def block_domain_handler(domain: str, ip_block: bool = Query(False)):
    print(f"/block/domain/{domain} called")

    error_message = block_domain(domain)
    if error_message is not None:
        return JSONResponse(status_code=500, content={"message": error_message})

    if ip_block:
        error_message = block_ip(domain)
        if error_message is not None:
            return JSONResponse(status_code=404, content={"message": error_message})

    message = f"{domain} is added to block list."
    if ip_block:
        message += f"{domain} IP is blocked also."
    return {"message": message}


@router.post("/ssh/boot_reservation")
async def ssh_boot_reservation():
    current_day = datetime.now().strftime("%A")
    allowed_days = {"Tuesday", "Wednesday", "Thursday", "Friday"}

    if current_day in allowed_days:
        if not os.path.exists(SSH_BOOT_RESERVATION_DIR):
            os.makedirs(SSH_BOOT_RESERVATION_DIR)
        open(SSH_BOOT_RESERVATION_FILE, "a").close()
        return {"message": "SSH boot reservation file created."}
    else:
        raise HTTPException(
            status_code=403,
            detail="SSH boot reservation is only allowed on Tuesday to Friday.",
        )


app.include_router(router)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
