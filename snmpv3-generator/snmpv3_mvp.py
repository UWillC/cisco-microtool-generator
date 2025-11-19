MODES = ["secure-default", "balanced", "legacy-compatible", "custom"]


def choose_mode():
    print("Available modes:")
    for m in MODES:
        print(f" - {m}")
    mode = input("Mode (secure-default / balanced / legacy-compatible / custom): ").strip().lower()

    if mode not in MODES:
        raise ValueError(f"Invalid mode: {mode}. Allowed: {', '.join(MODES)}")

    return mode


def get_non_empty(prompt: str) -> str:
    value = input(prompt).strip()
    if not value:
        raise ValueError(f"Value for '{prompt}' cannot be empty.")
    return value


def resolve_algorithms(mode: str):
    """
    Returns (auth_algo, priv_algo) based on selected mode.
    """
    if mode == "secure-default":
        # Nowocześnie, bezpiecznie – podejście domyślne
        return "SHA-256", "AES-256"
    elif mode == "balanced":
        # Dobra równowaga kompatybilność/bezpieczeństwo
        return "SHA", "AES-128"
    elif mode == "legacy-compatible":
        # Maksymalna kompatybilność w starszych środowiskach (wciąż bez MD5)
        return "SHA", "AES-128"
    elif mode == "custom":
        # Użytkownik sam decyduje
        auth_algo = get_non_empty("Auth algorithm (SHA/SHA-256/SHA-512): ")
        priv_algo = get_non_empty("Privacy algorithm (AES-128/AES-256): ")
        return auth_algo, priv_algo
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def generate_snmpv3(user, group, auth_algo, auth_pass, priv_algo, priv_pass, host):
    config = f"""
! SNMPv3 user and group
snmp-server view ALL iso included
snmp-server group {group} v3 priv read ALL write ALL
snmp-server user {user} {group} v3 auth {auth_algo} {auth_pass} priv {priv_algo} {priv_pass}

! SNMPv3 trap host
snmp-server host {host} version 3 priv {user}

! Recommended logging of SNMP
snmp-server enable traps
!
"""
    return config.strip()


def main():
    print("=== SNMPv3 Config Generator v0.2 ===\n")

    # 1. Tryb
    mode = choose_mode()
    print(f"\nSelected mode: {mode}\n")

    # 2. Dane wejściowe
    user = get_non_empty("SNMPv3 username: ")
    default_group = f"{user}_grp"
    group = input(f"Group name [{default_group}]: ").strip() or default_group

    host = get_non_empty("SNMP manager IP/hostname (trap host): ")

    auth_pass = get_non_empty("Auth password: ")
    priv_pass = get_non_empty("Privacy password: ")

    # 3. Algorytmy na podstawie trybu
    auth_algo, priv_algo = resolve_algorithms(mode)

    print("\nUsing algorithms:")
    print(f" - Auth : {auth_algo}")
    print(f" - Priv : {priv_algo}\n")

    # 4. Generowanie konfigu
    config = generate_snmpv3(
        user=user,
        group=group,
        auth_algo=auth_algo,
        auth_pass=auth_pass,
        priv_algo=priv_algo,
        priv_pass=priv_pass,
        host=host,
    )

    print("Generated SNMPv3 config:\n")
    print(config)
    print("\n! Copy-paste this into your Cisco device.\n")


if __name__ == "__main__":
    try:
        main()
    except ValueError as e:
        print(f"\n[ERROR] {e}")
        print("Aborting. Please run the script again with valid values.\n")
