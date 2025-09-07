import re

def get_interface_from_input(input_name, interfaces):
      for if_name, if_data in interfaces.items():
            if input_name.lower() == if_name.lower():
                  return if_name
            aliases = if_data.get("aliases") or []
            aliases = aliases.split(',')
            for alias in aliases:
                  if input_name.lower() == alias.lower():
                        return if_name
      return None


def warn_shadowing_extended(new_rules):
    saw_deny_any_any = False
    for line in new_rules:
        t = line.lower().split()
        if t[:4] == ["deny", "ip", "any", "any"]:
            saw_deny_any_any = True
        elif saw_deny_any_any:
            print(f"[WARN] Rule after 'deny ip any any' is shadowed: {line}")


def warn_shadowing_standard(new_rules):
    saw_deny_any = False
    for line in new_rules:
        t = line.lower().split()
        if t[:2] == ["deny", "any"]:
            saw_deny_any = True
        elif saw_deny_any:
            print(f"[WARN] Rule after 'deny any' is shadowed: {line}")


def acl_exists_in_show(show_text, acl_type, acl_id):
    pat = rf"^\s*{acl_type.capitalize()}\s+IP\s+access\s+list\s+{re.escape(acl_id)}\b"
    return re.search(pat, show_text, re.MULTILINE) is not None


def build_switch_cmds(vlan_id, vlan_name, svi_ip, svi_mask):
    cmds = [
        f"vlan {vlan_id}",
        f"name {vlan_name}",
        "exit",
    ]

    if svi_ip and svi_mask:
        cmds += [
            f"interface vlan {vlan_id}",
            f"ip address {svi_ip} {svi_mask}",
            "no shutdown",
            "exit",
        ]
    return cmds


def build_msw_cmds(vlan_id, vlan_name, svi_ip, svi_mask):
    cmds = [
        f"vlan {vlan_id}",
        f"name {vlan_name}",
        "exit",
        "ip routing",
        f"interface vlan {vlan_id}",
        f"ip address {svi_ip} {svi_mask}",
        "no shutdown",
        "exit",
    ]
    return cmds


def build_router_cmds(trunk_if, vlan_id, ip, mask, native=False):
    subif = f"{trunk_if}.{vlan_id}"
    encap = f"encapsulation dot1Q {vlan_id}" + (" native" if native else "")
    return [
        f"interface {trunk_if}",
        "no shutdown",
        "exit",
        f"interface {subif}",
        f"{encap}",
        f"ip address {ip} {mask}",
        "no shutdown",
        "exit",
    ]


def prefix_len_mask(prefix):
      mask = (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF
      return ".".join(str((mask >> s) & 0xFF) for s in (24, 16, 8, 0))


def get_vlan_id():
      while True:
            raw = input("VLAN ID (1-4094, avoid 1002-1005): ").strip()
            if not raw.isdigit():
                  print("[ERROR] VLAN ID must be a number.")
                  continue
            vid = int(raw)
            if 1 <= vid <= 4094 and vid not in {1002, 1003, 1004, 1005}:
                  return vid
            print("[ERROR] VLAN ID out of range or reserved.")


def get_vlan_name():
      while True:
            name = input("VLAN name: ").strip()
            if re.fullmatch(r"[A-Za-z0-9_\- ]{1,32}", name):
                  return name
            print("[ERROR] Invalid VLAN name format.")


def get_connected_ipv4(conn):
    out = conn.execute("show ip route connected")
    nets = []
    for line in str(out).splitlines():
        m = re.search(r'^\s*C\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+.*?,\s+(\S+)', line)
        if m:
            net, plen, iface = m.group(1), int(m.group(2)), m.group(3)
            nets.append((net, prefix_len_mask(plen), iface))
    return nets


def get_connected_ipv6(conn):
      out = conn.execute("show ipv6 route connected")
      nets = []
      for line in str(out).splitlines():
            m = re.search(r'^\s*C\s+([0-9A-Fa-f:]+)/(\d+)\s+.*?,\s+(\S+)', line)
            if m:
                  nets.append((m.group(1), int(m.group(2)), m.group(3)))
      return nets