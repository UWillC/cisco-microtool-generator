from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
import datetime

router = APIRouter()


# -----------------------------
# AAA / TACACS+ Request Schema
# -----------------------------
class AAARequest(BaseModel):
    device: str = "Cisco IOS XE"
    mode: str = "tacacs"  # tacacs | local-only

    # Common
    enable_secret: Optional[str] = None
    output_format: str = "cli"  # cli | oneline

    # TACACS+ specific
    tacacs1_name: Optional[str] = None
    tacacs1_ip: Optional[str] = None
    tacacs1_key: Optional[str] = None

    tacacs2_name: Optional[str] = None
    tacacs2_ip: Optional[str] = None
    tacacs2_key: Optional[str] = None

    source_interface: Optional[str] = None


# -----------------------------
# AAA logic (adapted from CLI)
# -----------------------------
def generate_aaa_local_only(enable_secret: Optional[str] = None) -> str:
    cfg = "\n! AAA local-only baseline\n"
    cfg += "aaa new-model\n"
    cfg += "aaa authentication login default local\n"
    cfg += "aaa authorization exec default local\n"
    cfg += "aaa accounting update periodic 15\n"

    if enable_secret:
        cfg += f"\n! Enable secret\nenable secret {enable_secret}\n"

    cfg += """
! Line configuration
line vty 0 4
 login local
 transport input ssh
!
"""
    return cfg.strip()


def generate_aaa_tacacs(req: AAARequest) -> str:
    cfg = "\n! AAA with TACACS+ and local fallback\n"
    cfg += "aaa new-model\n"
    cfg += "aaa authentication login default group tacacs+ local\n"
    cfg += "aaa authorization exec default group tacacs+ local\n"
    cfg += "aaa accounting update periodic 15\n"

    if req.enable_secret:
        cfg += f"\n! Enable secret\nenable secret {req.enable_secret}\n"

    cfg += "\n! TACACS+ server definitions\n"

    if not (req.tacacs1_name and req.tacacs1_ip and req.tacacs1_key):
        raise ValueError("Primary TACACS+ server definition is incomplete.")

    cfg += f"tacacs server {req.tacacs1_name}\n"
    cfg += f" address ipv4 {req.tacacs1_ip}\n"
    cfg += f" key {req.tacacs1_key}\n"

    if req.tacacs2_name and req.tacacs2_ip and req.tacacs2_key:
        cfg += f"\ntacacs server {req.tacacs2_name}\n"
        cfg += f" address ipv4 {req.tacacs2_ip}\n"
        cfg += f" key {req.tacacs2_key}\n"

    if req.source_interface:
        cfg += f"\n! TACACS+ source interface\nip tacacs source-interface {req.source_interface}\n"

    cfg += """
! Line configuration
line vty 0 4
 login authentication default
 transport input ssh
!
"""
    return cfg.strip()


def to_oneline(block: str) -> str:
    lines = []
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        lines.append(line)
    return " ; ".join(lines)


# -----------------------------
# AAA API Endpoint
# -----------------------------
@router.post("/aaa")
def generate_aaa(req: AAARequest):
    if req.mode not in ("tacacs", "local-only"):
        raise ValueError("Invalid mode. Allowed: 'tacacs', 'local-only'.")

    if req.mode == "local-only":
        cli_cfg = generate_aaa_local_only(enable_secret=req.enable_secret)
    else:
        cli_cfg = generate_aaa_tacacs(req)

    if req.output_format == "oneline":
        output = to_oneline(cli_cfg)
    else:
        output = cli_cfg

    return {
        "device": req.device,
        "mode": req.mode,
        "output_format": req.output_format,
        "config": output,
        "metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "module": "AAA / TACACS+ Generator",
            "tool": "Cisco Micro-Tool Generator"
        }
    }
