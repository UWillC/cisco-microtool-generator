"""
Config Parser Router

Parses Cisco IOS/IOS-XE show running-config output into structured JSON.
"""

from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import re


router = APIRouter()


class ConfigParseRequest(BaseModel):
    config_text: str = Field(..., description="Raw show running-config output")


class InterfaceInfo(BaseModel):
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    shutdown: bool = False
    switchport_mode: Optional[str] = None
    vlan: Optional[int] = None


class SNMPConfig(BaseModel):
    communities: List[Dict[str, str]] = []
    users: List[Dict[str, Any]] = []
    hosts: List[Dict[str, Any]] = []
    location: Optional[str] = None
    contact: Optional[str] = None


class NTPConfig(BaseModel):
    servers: List[Dict[str, Any]] = []
    source_interface: Optional[str] = None
    authentication_enabled: bool = False
    trusted_keys: List[int] = []


class LoggingConfig(BaseModel):
    buffer_size: Optional[int] = None
    console_level: Optional[str] = None
    hosts: List[str] = []
    source_interface: Optional[str] = None


class AAAConfig(BaseModel):
    new_model: bool = False
    authentication_lists: List[Dict[str, Any]] = []
    authorization_lists: List[Dict[str, Any]] = []
    accounting_lists: List[Dict[str, Any]] = []
    tacacs_servers: List[Dict[str, Any]] = []
    radius_servers: List[Dict[str, Any]] = []


class UserInfo(BaseModel):
    username: str
    privilege: Optional[int] = None
    secret_type: Optional[str] = None


class ConfigParseResponse(BaseModel):
    hostname: Optional[str] = None
    domain_name: Optional[str] = None
    enable_secret: bool = False
    service_password_encryption: bool = False
    interfaces: List[InterfaceInfo] = []
    snmp: SNMPConfig = SNMPConfig()
    ntp: NTPConfig = NTPConfig()
    logging: LoggingConfig = LoggingConfig()
    aaa: AAAConfig = AAAConfig()
    users: List[UserInfo] = []
    banner_motd: Optional[str] = None
    banner_login: Optional[str] = None
    raw_sections: Dict[str, str] = {}
    parse_warnings: List[str] = []


def parse_hostname(config: str) -> Optional[str]:
    match = re.search(r'^hostname\s+(\S+)', config, re.MULTILINE)
    return match.group(1) if match else None


def parse_domain(config: str) -> Optional[str]:
    match = re.search(r'^ip domain[- ]name\s+(\S+)', config, re.MULTILINE)
    return match.group(1) if match else None


def parse_interfaces(config: str) -> List[InterfaceInfo]:
    interfaces = []
    # Match interface blocks
    pattern = r'^interface\s+(\S+)\n((?:[ !].*\n)*?)(?=^!|^interface|\Z)'
    matches = re.findall(pattern, config, re.MULTILINE)

    for name, block in matches:
        iface = InterfaceInfo(name=name)

        # Description
        desc_match = re.search(r'^\s+description\s+(.+)$', block, re.MULTILINE)
        if desc_match:
            iface.description = desc_match.group(1).strip()

        # IP address
        ip_match = re.search(r'^\s+ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', block, re.MULTILINE)
        if ip_match:
            iface.ip_address = ip_match.group(1)
            iface.subnet_mask = ip_match.group(2)

        # Shutdown
        if re.search(r'^\s+shutdown\s*$', block, re.MULTILINE):
            iface.shutdown = True

        # Switchport mode
        mode_match = re.search(r'^\s+switchport mode\s+(\S+)', block, re.MULTILINE)
        if mode_match:
            iface.switchport_mode = mode_match.group(1)

        # Access VLAN
        vlan_match = re.search(r'^\s+switchport access vlan\s+(\d+)', block, re.MULTILINE)
        if vlan_match:
            iface.vlan = int(vlan_match.group(1))

        interfaces.append(iface)

    return interfaces


def parse_snmp(config: str) -> SNMPConfig:
    snmp = SNMPConfig()

    # Communities
    for match in re.finditer(r'^snmp-server community\s+(\S+)\s+(RO|RW)(?:\s+(\S+))?$', config, re.MULTILINE):
        community = {"name": match.group(1), "access": match.group(2)}
        if match.group(3):
            community["acl"] = match.group(3)
        snmp.communities.append(community)

    # Users (SNMPv3)
    for match in re.finditer(r'^snmp-server user\s+(\S+)\s+(\S+)(?:\s+v3)?(?:\s+auth\s+(\S+))?', config, re.MULTILINE):
        user = {"username": match.group(1), "group": match.group(2)}
        if match.group(3):
            user["auth"] = match.group(3)
        snmp.users.append(user)

    # Hosts
    for match in re.finditer(r'^snmp-server host\s+(\S+)(?:\s+version\s+(\S+))?(?:\s+(\S+))?', config, re.MULTILINE):
        host = {"address": match.group(1)}
        if match.group(2):
            host["version"] = match.group(2)
        if match.group(3):
            host["community_or_user"] = match.group(3)
        snmp.hosts.append(host)

    # Location
    loc_match = re.search(r'^snmp-server location\s+(.+)$', config, re.MULTILINE)
    if loc_match:
        snmp.location = loc_match.group(1).strip()

    # Contact
    contact_match = re.search(r'^snmp-server contact\s+(.+)$', config, re.MULTILINE)
    if contact_match:
        snmp.contact = contact_match.group(1).strip()

    return snmp


def parse_ntp(config: str) -> NTPConfig:
    ntp = NTPConfig()

    # Servers
    for match in re.finditer(r'^ntp server\s+(\S+)(?:\s+key\s+(\d+))?(?:\s+(prefer))?', config, re.MULTILINE):
        server = {"address": match.group(1)}
        if match.group(2):
            server["key"] = int(match.group(2))
        if match.group(3):
            server["prefer"] = True
        ntp.servers.append(server)

    # Source interface
    src_match = re.search(r'^ntp source\s+(\S+)', config, re.MULTILINE)
    if src_match:
        ntp.source_interface = src_match.group(1)

    # Authentication
    if re.search(r'^ntp authenticate\s*$', config, re.MULTILINE):
        ntp.authentication_enabled = True

    # Trusted keys
    for match in re.finditer(r'^ntp trusted-key\s+(\d+)', config, re.MULTILINE):
        ntp.trusted_keys.append(int(match.group(1)))

    return ntp


def parse_logging(config: str) -> LoggingConfig:
    logging = LoggingConfig()

    # Buffer size
    buf_match = re.search(r'^logging buffered\s+(\d+)', config, re.MULTILINE)
    if buf_match:
        logging.buffer_size = int(buf_match.group(1))

    # Console level
    console_match = re.search(r'^logging console\s+(\S+)', config, re.MULTILINE)
    if console_match:
        logging.console_level = console_match.group(1)

    # Hosts
    for match in re.finditer(r'^logging host\s+(\S+)', config, re.MULTILINE):
        logging.hosts.append(match.group(1))

    # Also match "logging X.X.X.X" format
    for match in re.finditer(r'^logging\s+(\d+\.\d+\.\d+\.\d+)', config, re.MULTILINE):
        if match.group(1) not in logging.hosts:
            logging.hosts.append(match.group(1))

    # Source interface
    src_match = re.search(r'^logging source-interface\s+(\S+)', config, re.MULTILINE)
    if src_match:
        logging.source_interface = src_match.group(1)

    return logging


def parse_aaa(config: str) -> AAAConfig:
    aaa = AAAConfig()

    # New model
    if re.search(r'^aaa new-model\s*$', config, re.MULTILINE):
        aaa.new_model = True

    # Authentication lists
    for match in re.finditer(r'^aaa authentication\s+(\S+)\s+(\S+)\s+(.+)$', config, re.MULTILINE):
        aaa.authentication_lists.append({
            "type": match.group(1),
            "name": match.group(2),
            "methods": match.group(3).strip()
        })

    # Authorization lists
    for match in re.finditer(r'^aaa authorization\s+(\S+)\s+(\S+)\s+(.+)$', config, re.MULTILINE):
        aaa.authorization_lists.append({
            "type": match.group(1),
            "name": match.group(2),
            "methods": match.group(3).strip()
        })

    # Accounting lists
    for match in re.finditer(r'^aaa accounting\s+(\S+)\s+(\S+)\s+(.+)$', config, re.MULTILINE):
        aaa.accounting_lists.append({
            "type": match.group(1),
            "name": match.group(2),
            "methods": match.group(3).strip()
        })

    # TACACS servers
    for match in re.finditer(r'^tacacs server\s+(\S+)', config, re.MULTILINE):
        aaa.tacacs_servers.append({"name": match.group(1)})

    # Legacy TACACS host
    for match in re.finditer(r'^tacacs-server host\s+(\S+)', config, re.MULTILINE):
        aaa.tacacs_servers.append({"address": match.group(1)})

    return aaa


def parse_users(config: str) -> List[UserInfo]:
    users = []

    for match in re.finditer(r'^username\s+(\S+)(?:\s+privilege\s+(\d+))?\s+secret\s+(\d+)', config, re.MULTILINE):
        user = UserInfo(
            username=match.group(1),
            privilege=int(match.group(2)) if match.group(2) else None,
            secret_type=match.group(3)
        )
        users.append(user)

    return users


def parse_banners(config: str) -> tuple[Optional[str], Optional[str]]:
    motd = None
    login = None

    # Banner MOTD - handle multi-line with delimiter
    motd_match = re.search(r'^banner motd\s*(\S)(.*?)\1', config, re.MULTILINE | re.DOTALL)
    if motd_match:
        motd = motd_match.group(2).strip()

    # Banner login
    login_match = re.search(r'^banner login\s*(\S)(.*?)\1', config, re.MULTILINE | re.DOTALL)
    if login_match:
        login = login_match.group(2).strip()

    return motd, login


@router.post("/config/parse", response_model=ConfigParseResponse)
def parse_config(req: ConfigParseRequest):
    """
    Parse Cisco IOS/IOS-XE running configuration into structured JSON.

    Accepts raw 'show running-config' output and extracts:
    - Basic info (hostname, domain)
    - Interfaces with IP addresses
    - SNMP configuration
    - NTP configuration
    - Logging settings
    - AAA/TACACS configuration
    - Local users
    - Banners
    """
    config = req.config_text
    warnings = []

    # Parse all sections
    hostname = parse_hostname(config)
    if not hostname:
        warnings.append("Could not find hostname - is this a valid Cisco config?")

    domain = parse_domain(config)
    interfaces = parse_interfaces(config)
    snmp = parse_snmp(config)
    ntp = parse_ntp(config)
    logging_cfg = parse_logging(config)
    aaa = parse_aaa(config)
    users = parse_users(config)
    banner_motd, banner_login = parse_banners(config)

    # Check for enable secret
    enable_secret = bool(re.search(r'^enable secret', config, re.MULTILINE))

    # Check for service password-encryption
    svc_pwd_enc = bool(re.search(r'^service password-encryption', config, re.MULTILINE))

    return ConfigParseResponse(
        hostname=hostname,
        domain_name=domain,
        enable_secret=enable_secret,
        service_password_encryption=svc_pwd_enc,
        interfaces=interfaces,
        snmp=snmp,
        ntp=ntp,
        logging=logging_cfg,
        aaa=aaa,
        users=users,
        banner_motd=banner_motd,
        banner_login=banner_login,
        parse_warnings=warnings
    )


@router.post("/config/parse/summary")
def parse_config_summary(req: ConfigParseRequest):
    """
    Returns a quick summary/overview of the configuration.
    """
    config = req.config_text

    hostname = parse_hostname(config)
    interfaces = parse_interfaces(config)

    # Count various elements
    active_interfaces = [i for i in interfaces if not i.shutdown]
    l3_interfaces = [i for i in interfaces if i.ip_address]

    snmp = parse_snmp(config)
    ntp = parse_ntp(config)
    aaa = parse_aaa(config)
    users = parse_users(config)

    return {
        "hostname": hostname,
        "summary": {
            "total_interfaces": len(interfaces),
            "active_interfaces": len(active_interfaces),
            "l3_interfaces": len(l3_interfaces),
            "snmp_communities": len(snmp.communities),
            "snmp_v3_users": len(snmp.users),
            "ntp_servers": len(ntp.servers),
            "aaa_enabled": aaa.new_model,
            "local_users": len(users),
            "tacacs_servers": len(aaa.tacacs_servers)
        }
    }
