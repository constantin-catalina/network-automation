ROLES = {
    "router": {"vlan", "routing", "acl", "ipv6", "dhcp", "nat", "save", "backup", "compare", "ping"},
    "switch": {"vlan", "acl", "ipv6", "save", "backup", "compare", "ping"},
    "msw":    {"vlan", "routing", "acl", "ipv6", "save", "backup", "compare", "ping"},
    "host":   {"ping"}
    }

BASELINE = {"ping"}

def get_role(devices_data, name):
      conn = (devices_data.get(name) or {})
      return (conn.get("role") or "").lower()

def get_caps(devices_data, name):
      role = get_role(devices_data, name)
      caps = set()
      if role in ROLES:
            caps |= ROLES[role]
      return caps | BASELINE

def filter_devices(devices_data, required_cap=None, roles=None):
      out = []
      role_filter = {r.lower() for r in roles} if roles else None

      for name in devices_data.keys():
            role = get_role(devices_data, name)
            if role_filter and role not in role_filter:
                  continue

            caps = get_caps(devices_data, name)
            if required_cap and required_cap not in caps:
                  continue
            out.append(name)

      return out

def print_device_list(names, title):
      print("\n============= OPTIONS =============")
      if not names:
            print("[ERROR] No eligible devices.")
            return

      print(title)
      for n in names:
            print(f"  - {n}")

      print("===================================\n")

def pick_from_list(valid):
      if not valid:
            return None
      choice = input("Select a device: ").strip()

      if choice in valid:
            return choice

      print("[ERROR] Invalid device choice. Please try again.")
      return None