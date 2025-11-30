from fastapi import APIRouter
from pydantic import BaseModel
import datetime
from typing import Optional

router = APIRouter()


# -----------------------------
# NTP Request Schema
# -----------------------------
class NTPRequest(BaseModel):
    device: str = "Cisco IOS XE"
    primary_server: str
    secondary_server: Optional[str] = None
    timezone: str = "UTC"
    use_auth: bool = False
    key_id: Optional[str] = None
    key_value: Optional[str] = None
    output_format: str = "cli"


# -----------------------------
# NTP Logic (API-adapted)
# -----------------------------
def generate_ntp_cli(req: NTPRequest) -> str:
    cfg = f"""
clock timezone {req.timezone}
ntp server {req.primary_server}
"""
    if req.secondary_server:
        cfg += f"ntp server {req.secondary_server}\n"

    if req.use_auth and req.key_id and req.key_value:
        cfg += f"""
ntp authenticate
ntp authentication-key {req.key_id} md5 {req.key_value}
ntp trusted-key {req.key_id}
"""

    return cfg.strip()


def generate_ntp_oneline(cli_text: str) -> str:
    lines = []
    for line in cli_text.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        lines.append(line)
    return " ; ".join(lines)


# -----------------------------
# NTP API Endpoint
# -----------------------------
@router.post("/ntp")
def generate_ntp(req: NTPRequest):
    cli_config = generate_ntp_cli(req)

    if req.output_format == "oneline":
        output = generate_ntp_oneline(cli_config)
    else:
        output = cli_config

    return {
        "device": req.device,
        "output_format": req.output_format,
        "config": output,
        "metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "module": "NTP Generator",
            "tool": "Cisco Micro-Tool Generator",
        },
    }
