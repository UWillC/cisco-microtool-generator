from fastapi import APIRouter
from pydantic import BaseModel
import datetime
from typing import Optional

router = APIRouter()


# --------------------------------------------------------------------
# REQUEST SCHEMA
# --------------------------------------------------------------------
class GoldenConfigRequest(BaseModel):
    device: str = "Cisco IOS XE"
    mode: str = "standard"       # standard | secure | hardened
    snmpv3_config: Optional[str] = None
    ntp_config: Optional[str] = None
    aaa_config: Optional[str] = None
    output_format: str = "cli"   # cli | oneline


# --------------------------------------------------------------------
# STATIC SECTIONS
# --------------------------------------------------------------------
def generate_banner():
    return """banner login ^
Unauthorized access to this device is prohibited.
All activity is monitored.
^
"""


def generate_logging():
    return """
! Logging baseline
service timestamps debug datetime localtime
service timestamps log datetime localtime
logging buffered 64000 warnings
logging console warnings
"""


def generate_security_baseline(mode: str):
    base = """
! Security baseline
no ip http server
no ip http secure-server
ip ssh version 2
ip ssh authentication-retries 3
ip ssh time-out 60
"""

    if mode == "secure":
        base += """
ip ssh cipher aes256-ctr
ip ssh key-exchange group14-sha256
"""

    if mode == "hardened":
        base += """
ip ssh cipher aes256-ctr aes192-ctr aes128-ctr
ip ssh key-exchange group16-sha512
ip ssh key-exchange group14-sha256
no cdp run
no lldp run
"""

    return base


# --------------------------------------------------------------------
# ASSEMBLER
# --------------------------------------------------------------------
def assemble_golden(req: GoldenConfigRequest):
    sections = []

    # Provided configs
    if req.snmpv3_config:
        sections.append(f"! SNMPv3\n{req.snmpv3_config}")

    if req.ntp_config:
        sections.append(f"! NTP\n{req.ntp_config}")

    if req.aaa_config:
        sections.append(f"! AAA\n{req.aaa_config}")

    # Built-in sections
    sections.append("! Banner\n" + generate_banner())
    sections.append("! Logging\n" + generate_logging())
    sections.append("! Security\n" + generate_security_baseline(req.mode))

    final = "\n\n".join(sections)

    if req.output_format == "oneline":
        lines = []
        for line in final.splitlines():
            line = line.strip()
            if not line or line.startswith("!"):
                continue
            lines.append(line)
        final = " ; ".join(lines)

    return final


# --------------------------------------------------------------------
# API ENDPOINT
# --------------------------------------------------------------------
@router.post("/golden-config")
def generate_golden_config(req: GoldenConfigRequest):

    final_cfg = assemble_golden(req)

    return {
        "device": req.device,
        "mode": req.mode,
        "output_format": req.output_format,
        "config": final_cfg,
        "metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "module": "Golden Config Builder",
            "tool": "Cisco Micro-Tool Generator"
        }
    }
