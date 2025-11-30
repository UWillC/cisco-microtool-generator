from fastapi import APIRouter
from pydantic import BaseModel
import datetime

router = APIRouter()


# -----------------------------
# SNMPv3 Request Schema
# -----------------------------
class SNMPv3Request(BaseModel):
    mode: str = "secure-default"
    device: str = "Cisco IOS XE"
    host: str
    user: str
    group: str
    auth_password: str
    priv_password: str
    output_format: str = "cli"


# -----------------------------
# SNMPv3 Logic (API-adapted)
# -----------------------------
def generate_snmpv3_cli(user, group, mode, host, auth_pass, priv_pass):
    algorithms = {
        "secure-default": ("SHA-256", "AES-256"),
        "balanced": ("SHA", "AES-128"),
        "legacy-compatible": ("SHA", "AES-128"),
    }

    auth_algo, priv_algo = algorithms.get(mode, ("SHA", "AES-128"))

    cfg = f"""
snmp-server view ALL iso included
snmp-server group {group} v3 priv read ALL write ALL
snmp-server user {user} {group} v3 auth {auth_algo} {auth_pass} priv {priv_algo} {priv_pass}
snmp-server host {host} version 3 priv {user}
snmp-server enable traps
"""
    return cfg.strip()


def generate_snmpv3_oneline(cli_text: str):
    lines = []
    for line in cli_text.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        lines.append(line)
    return " ; ".join(lines)


# -----------------------------
# SNMPv3 API Endpoint
# -----------------------------
@router.post("/snmpv3")
def generate_snmpv3(req: SNMPv3Request):

    cli_config = generate_snmpv3_cli(
        user=req.user,
        group=req.group,
        mode=req.mode,
        host=req.host,
        auth_pass=req.auth_password,
        priv_pass=req.priv_password,
    )

    if req.output_format == "oneline":
        output = generate_snmpv3_oneline(cli_config)
    else:
        output = cli_config

    return {
        "mode": req.mode,
        "device": req.device,
        "output_format": req.output_format,
        "config": output,
        "metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "module": "SNMPv3 Generator",
            "tool": "Cisco Micro-Tool Generator"
        }
    }
