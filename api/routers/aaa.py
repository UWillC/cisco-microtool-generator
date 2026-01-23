from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
import datetime

router = APIRouter()


# -----------------------------
# AAA / TACACS+ Request Schema (v2 - Best Practices)
# -----------------------------
class AAARequest(BaseModel):
    device: str = "Cisco IOS XE"
    mode: str = "tacacs"  # tacacs | local-only

    # Common
    enable_secret: Optional[str] = None
    use_sha256_secret: bool = False  # Type 8 password (algorithm-type sha256)
    output_format: str = "cli"  # cli | oneline | template

    # Local fallback user (for console access when TACACS+ is down)
    local_username: Optional[str] = None
    local_password: Optional[str] = None

    # SSH Prerequisites (required for transport input ssh)
    domain_name: Optional[str] = None  # ip domain-name
    ssh_modulus: str = "2048"  # RSA key size: 2048 / 4096
    ssh_version: str = "2"  # SSH version: 2 (recommended) / 1.99

    # TACACS+ specific
    tacacs_group_name: str = "TAC-SERVERS"  # Server group name

    tacacs1_name: Optional[str] = None
    tacacs1_ip: Optional[str] = None
    tacacs1_key: Optional[str] = None

    tacacs2_name: Optional[str] = None
    tacacs2_ip: Optional[str] = None
    tacacs2_key: Optional[str] = None

    source_interface: Optional[str] = None
    server_timeout: Optional[int] = None  # Timeout in seconds (default: 5)

    # Accounting options (best practice: enable both)
    use_exec_accounting: bool = True  # Track login/logout sessions
    use_command_accounting: bool = True  # Track privileged commands (level 15)


# -----------------------------
# AAA logic (adapted from CLI)
# -----------------------------
def generate_aaa_local_only(req: AAARequest) -> str:
    lines = []

    # Section: SSH Prerequisites
    if req.domain_name:
        lines.append("!")
        lines.append("! === SSH Prerequisites ===")
        lines.append(f"ip domain-name {req.domain_name}")
        lines.append(f"crypto key generate rsa modulus {req.ssh_modulus}")
        lines.append(f"ip ssh version {req.ssh_version}")

    # Section: AAA Configuration
    lines.append("!")
    lines.append("! === AAA Local-Only Baseline ===")
    lines.append("aaa new-model")
    lines.append("aaa authentication login default local")
    lines.append("aaa authorization exec default local")
    lines.append("! Note: Accounting requires external server (TACACS+/RADIUS)")

    # Section: Enable Secret
    if req.enable_secret:
        lines.append("!")
        lines.append("! === Enable Secret ===")
        if req.use_sha256_secret:
            lines.append(f"enable algorithm-type sha256 secret {req.enable_secret}")
        else:
            lines.append(f"enable secret {req.enable_secret}")

    # Section: Local User (fallback for console)
    if req.local_username and req.local_password:
        lines.append("!")
        lines.append("! === Local User (console fallback) ===")
        if req.use_sha256_secret:
            lines.append(f"username {req.local_username} privilege 15 algorithm-type sha256 secret {req.local_password}")
        else:
            lines.append(f"username {req.local_username} privilege 15 secret {req.local_password}")

    # Section: Line VTY
    lines.append("!")
    lines.append("! === Line Configuration ===")
    lines.append("line vty 0 4")
    lines.append(" login local")
    lines.append(" transport input ssh")
    lines.append("!")

    return "\n".join(lines)


def generate_aaa_tacacs(req: AAARequest) -> str:
    lines = []
    group_name = req.tacacs_group_name or "TAC-SERVERS"

    if not (req.tacacs1_name and req.tacacs1_ip and req.tacacs1_key):
        raise ValueError("Primary TACACS+ server definition is incomplete.")

    # Section: SSH Prerequisites
    if req.domain_name:
        lines.append("!")
        lines.append("! === SSH Prerequisites ===")
        lines.append(f"ip domain-name {req.domain_name}")
        lines.append(f"crypto key generate rsa modulus {req.ssh_modulus}")
        lines.append(f"ip ssh version {req.ssh_version}")

    # Section: AAA Configuration
    lines.append("!")
    lines.append("! === AAA Configuration (TACACS+ with local fallback) ===")
    lines.append("aaa new-model")
    lines.append(f"aaa authentication login default group {group_name} local")
    lines.append(f"aaa authorization exec default group {group_name} local if-authenticated")

    # Section: Accounting
    lines.append("!")
    lines.append("! === AAA Accounting ===")
    if req.use_exec_accounting:
        lines.append(f"aaa accounting exec default start-stop group {group_name}")
    if req.use_command_accounting:
        lines.append(f"aaa accounting commands 15 default start-stop group {group_name}")
    if not req.use_exec_accounting and not req.use_command_accounting:
        lines.append("! Accounting disabled (not recommended)")

    # Section: Enable Secret
    if req.enable_secret:
        lines.append("!")
        lines.append("! === Enable Secret ===")
        if req.use_sha256_secret:
            lines.append(f"enable algorithm-type sha256 secret {req.enable_secret}")
        else:
            lines.append(f"enable secret {req.enable_secret}")

    # Section: Local Fallback User (for console when TACACS+ is down)
    if req.local_username and req.local_password:
        lines.append("!")
        lines.append("! === Local Fallback User (console access when TACACS+ down) ===")
        if req.use_sha256_secret:
            lines.append(f"username {req.local_username} privilege 15 algorithm-type sha256 secret {req.local_password}")
        else:
            lines.append(f"username {req.local_username} privilege 15 secret {req.local_password}")

    # Section: TACACS+ Server Definitions
    lines.append("!")
    lines.append("! === TACACS+ Server Definitions ===")

    # Primary server
    lines.append(f"tacacs server {req.tacacs1_name}")
    lines.append(f" address ipv4 {req.tacacs1_ip}")
    lines.append(f" key {req.tacacs1_key}")
    if req.server_timeout:
        lines.append(f" timeout {req.server_timeout}")

    # Secondary server (optional)
    if req.tacacs2_name and req.tacacs2_ip and req.tacacs2_key:
        lines.append("!")
        lines.append(f"tacacs server {req.tacacs2_name}")
        lines.append(f" address ipv4 {req.tacacs2_ip}")
        lines.append(f" key {req.tacacs2_key}")
        if req.server_timeout:
            lines.append(f" timeout {req.server_timeout}")

    # Section: Server Group
    lines.append("!")
    lines.append("! === TACACS+ Server Group ===")
    lines.append(f"aaa group server tacacs+ {group_name}")
    lines.append(f" server name {req.tacacs1_name}")
    if req.tacacs2_name and req.tacacs2_ip and req.tacacs2_key:
        lines.append(f" server name {req.tacacs2_name}")

    # Section: Source Interface
    if req.source_interface:
        lines.append("!")
        lines.append("! === TACACS+ Source Interface ===")
        lines.append(f"ip tacacs source-interface {req.source_interface}")

    # Section: Line Configuration
    lines.append("!")
    lines.append("! === Line Configuration ===")
    lines.append("line vty 0 4")
    lines.append(" login authentication default")
    lines.append(" transport input ssh")
    lines.append("!")

    return "\n".join(lines)


def to_oneline(block: str) -> str:
    lines = []
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        lines.append(line)
    return " ; ".join(lines)


def generate_aaa_template(req: AAARequest) -> str:
    """Generate YAML template for automation tools (Ansible, Netmiko, etc.)"""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    group_name = req.tacacs_group_name or "TAC-SERVERS"

    # Build TACACS servers list
    tacacs_servers = []
    if req.mode == "tacacs":
        if req.tacacs1_name and req.tacacs1_ip:
            tacacs_servers.append({
                "name": req.tacacs1_name,
                "ip": req.tacacs1_ip,
                "key": req.tacacs1_key or ""
            })
        if req.tacacs2_name and req.tacacs2_ip:
            tacacs_servers.append({
                "name": req.tacacs2_name,
                "ip": req.tacacs2_ip,
                "key": req.tacacs2_key or ""
            })

    # Pre-compute values
    login_default = f"group {group_name} local" if req.mode == "tacacs" else "local"
    exec_default = f"group {group_name} local if-authenticated" if req.mode == "tacacs" else "local"
    enable_secret_val = f'"{req.enable_secret}"' if req.enable_secret else "null"
    source_iface_val = f'"{req.source_interface}"' if req.source_interface else "null"
    timeout_val = req.server_timeout if req.server_timeout else "null"
    login_type = "authentication default" if req.mode == "tacacs" else "local"
    domain_name_val = f'"{req.domain_name}"' if req.domain_name else "null"
    local_username_val = f'"{req.local_username}"' if req.local_username else "null"
    local_password_val = f'"{req.local_password}"' if req.local_password else "null"

    yaml = f"""# AAA/TACACS+ YAML config generated by NetDevOps Micro-Tools
# Mode: {req.mode}
# Date: {now}
# Device: {req.device}

aaa_config:
  mode: "{req.mode}"

  ssh_prerequisites:
    domain_name: {domain_name_val}
    rsa_modulus: "{req.ssh_modulus}"
    ssh_version: "{req.ssh_version}"

  aaa_settings:
    new_model: true
    authentication:
      login_default: "{login_default}"
    authorization:
      exec_default: "{exec_default}"
    accounting:
      exec_enabled: {str(req.use_exec_accounting).lower()}
      commands_15_enabled: {str(req.use_command_accounting).lower()}

  credentials:
    enable_secret:
      value: {enable_secret_val}
      use_sha256: {str(req.use_sha256_secret).lower()}
    local_fallback_user:
      username: {local_username_val}
      password: {local_password_val}
      privilege: 15

  tacacs_group:
    name: "{group_name}"
    servers:"""

    if tacacs_servers:
        for srv in tacacs_servers:
            srv_name = srv["name"]
            srv_ip = srv["ip"]
            srv_key = srv["key"]
            yaml += f"""
      - name: "{srv_name}"
        address: "{srv_ip}"
        key: "{srv_key}"
        timeout: {timeout_val}"""
    else:
        yaml += " []"

    yaml += f"""

  source_interface: {source_iface_val}

  line_vty:
    range: "0 4"
    login: "{login_type}"
    transport_input: "ssh"
"""
    return yaml.strip()


# -----------------------------
# AAA API Endpoint
# -----------------------------
@router.post("/aaa")
def generate_aaa(req: AAARequest):
    if req.mode not in ("tacacs", "local-only"):
        raise ValueError("Invalid mode. Allowed: 'tacacs', 'local-only'.")

    if req.output_format == "template":
        output = generate_aaa_template(req)
    else:
        if req.mode == "local-only":
            cli_cfg = generate_aaa_local_only(req)
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
            "module": "AAA / TACACS+ Generator v2",
            "tool": "NetDevOps Micro-Tools"
        }
    }
