import yaml
import difflib
import os
import re
import ipaddress

from connection import DeviceConnection
from role_filter import *
from validation import *
from exceptions import *
from utils import *

# === Încarcă datele din devices.yaml ===
try:
    with open("devices.yaml") as file:
        devices_data = yaml.safe_load(file) or {}
except FileNotFoundError:
    print("[ERROR] devices.yaml file not found.")
    devices_data = {}

# === Cerinta 1a ===
def get_ipv4_and_mask(optional=False):
      while True:
            ip = input("SVI/Subinterface IPv4 " + ("or Enter to skip" if optional else "") + ": ").strip()
            if optional and ip == "":
                  return None, None
            try:
                  check_valid_ipv4_address(ip)
            except InvalidIPv4Address as e:
                  print(e)
                  continue

            mask = input("Netmask: ").strip()
            try:
                ok = check_valid_netmask(mask)
                if not ok:
                    print(f"[ERROR] Invalid netmask: {mask}")
                    continue

            except InvalidIPv4Address as exc:
                print(f"{exc}")
                continue

            except ValueError as exc:
                print(f"[ERROR] {exc}")
                continue

            try:
                ip_int = ip_to_int(ip)
                mask_int = ip_to_int(mask)
            except ValueError as exc:
                print(f"[ERROR] {exc}")
                continue

            network_int = ip_int & mask_int
            broadcast_int = network_int | (~mask_int & 0xFFFFFFFF)

            if ip_int == network_int:
                print(f"[ERROR] {ip} is the network address for mask {mask}. Choose a host address.")
                continue

            if ip_int == broadcast_int:
                print(f"[ERROR] {ip} is the broadcast address for mask {mask}. Choose a host address.")
                continue

            return ip, mask


def basic_vlan_config(hostname):
      '''
      Primeste numele unui device ca parametru si:
      - stabileste conexiunea
      - cere un vlan id
      - cere un vlan name
      - configureaza vlanul
      - inchide conexiunea
      '''

      if hostname not in devices_data:
            print(f"[ERROR] Unknown device '{hostname}'.")
            return

      role = devices_data[hostname].get("role")
      if role not in {"switch", "msw", "router"}:
        print(f"[ERROR] Unsupported role for '{hostname}': {role}")
        return

      vlan_id = get_vlan_id()
      vlan_name = get_vlan_name()

      if role == "switch":
            svi_ip, svi_mask = get_ipv4_and_mask(optional=True)
            vlan_cmds = build_switch_cmds(vlan_id, vlan_name, svi_ip, svi_mask)

      elif role == "msw":
            svi_ip, svi_mask = get_ipv4_and_mask(optional=False)
            vlan_cmds = build_msw_cmds(vlan_id, vlan_name, svi_ip, svi_mask)

      else:
            trunk_if = input("Router trunk interface (default g0/0): ").strip() or "g0/0"
            svi_ip, svi_mask = get_ipv4_and_mask(optional=False)
            native = (vlan_id == 99)
            vlan_cmds = build_router_cmds(trunk_if, vlan_id, svi_ip, svi_mask, native=native)

      conn = None
      try:
            conn = DeviceConnection(devices_data[hostname]['connection'])
            conn.connect()
            print(f"[INFO] Connected to {hostname}.")

            conn.execute(vlan_cmds)
            print(f"[INFO] VLAN {vlan_id} configured on {hostname} ({role}).")

      except Exception as e:
            print(f"[ERROR] Connection to {hostname} failed: {e}")

      finally:
          if conn:
            conn.disconnect()
            print(f'[INFO] Disconnected from {hostname}')


# === Cerinta 2a + optional 2 ===
def is_next_hop_direct_v4(conn, next_hop: str):
    for net, mask, iface in get_connected_ipv4(conn):
        if ip_in_network(next_hop, net, mask):
            return True, iface, (net, mask)
    return False, None, None


def is_next_hop_direct_v6(conn, next_hop: str):
      nh = ipaddress.IPv6Address(next_hop)
      for net, plen, iface in get_connected_ipv6(conn):
            if nh in ipaddress.IPv6Network(f"{net}/{plen}"):
                  return True, iface, (net, plen)
      return False, None, None


def static_routing(hostname):
      '''
      Primeste numele unui device ca parametru si:
      - stabileste conexiunea
      - permite meniu alegere ruta statica pe ipv4 sau pe ipv6
      IPV4:
      - cere net_add si mask_add pentru reteaua in care sa se duca (verificare sa fie adrese valide)
      - cere next_hop (verificare sa fie adrese valide)
      - trimite comanda ip route net_add mask_add next_hop
      - inchide conexiunea
      IPV6:
      - cere net_add si prefix pentru reteaua in care sa se duca (verificare sa fie adresa valida)
      - cere next_hop (verificare sa fie adrese valide)
      - trimite comanda ipv6 route net_add/prefix next_hop
      - inchide conexiunea
      Extra: stergere ruta
      '''

      if hostname not in devices_data:
            print(f"[ERROR] Unknown device '{hostname}'.")
            return

      device_role = devices_data[hostname]['role']

      if device_role != 'router' and device_role != 'msw':
          print(f"[ERROR] Device {hostname} is not a router or MSW.")
          return

      conn = None
      try:
            conn = DeviceConnection(devices_data[hostname]['connection'])
            conn.connect()
            print(f"[INFO] Connected to {hostname}.")

            while True:
                  print("\n===============================================")
                  print("============= STATIC ROUTING MENU =============")
                  print("===============================================")
                  print("1. IPv4 Route")
                  print("2. IPv6 Route")
                  print("3. Remove IPv4 Route")
                  print("4. Remove IPv6 Route")
                  print("0. Exit")
                  print("===============================================\n")
                  choice = input("Enter your choice: ").strip()

                  if choice == '1':
                        print("[INFO] IPv4 Route")
                        net_add = input("Enter network address: ").strip()
                        while True:
                              try:
                                    check_valid_ipv4_address(net_add)
                                    break
                              except InvalidIPv4Address as e:
                                    print(e)
                                    net_add = input("Enter network address: ").strip()

                        netmask = input("Enter netmask: ").strip()
                        while not check_valid_netmask(netmask):
                              print(f"[ERROR] Invalid netmask: {netmask}")
                              netmask = input("Enter valid netmask: ").strip()

                        if not check_valid_ipv4_network(net_add, netmask):
                              print(f"[ERROR] Network address {net_add} is not valid for netmask {netmask}.")
                              continue

                        next_hop = input("Enter next hop: ").strip()
                        while True:
                              try:
                                    check_valid_ipv4_address(next_hop)
                                    break
                              except InvalidIPv4Address as e:
                                    print(e)
                                    next_hop = input("Enter next hop: ").strip()

                        ok, exit_if, _ = is_next_hop_direct_v4(conn, next_hop)
                        if not ok:
                              print(f"[ERROR] Next-hop {next_hop} is not configured in any direct connected networks.")
                              continue

                        conn.execute([f"ip route {net_add} {netmask} {next_hop}"])

                  elif choice == '2':
                        print("[INFO] IPv6 Route")
                        net_add = input("Enter network address: ").strip()
                        while not check_valid_ipv6_address(net_add):
                              print(f"[ERROR] Invalid network address: {net_add}")
                              net_add = input("Enter valid network address: ").strip()

                        prefix = input("Enter prefix: ").strip()
                        prefix = int(prefix)
                        while prefix < 0 or prefix > 128:
                              print(f"[ERROR] Invalid prefix: {prefix}")
                              prefix = input("Enter valid prefix: ").strip()
                              prefix = int(prefix)

                        next_hop = input("Enter next hop: ").strip()
                        while not check_valid_ipv6_address(next_hop):
                              print(f"[ERROR] Invalid next hop: {next_hop}")
                              next_hop = input("Enter valid next hop: ").strip()

                        while True:
                              try:
                                    check_valid_ipv4_address(net_add)
                                    break
                              except InvalidIPv4Address as e:
                                    print(e)
                                    net_add = input("Enter network address: ").strip()

                        ok, exit_if, _ = is_next_hop_direct_v4(conn, next_hop)
                        if not ok:
                              print(f"[ERROR] Next-hop {next_hop} is not configured in any direct connected networks.")
                              continue

                        conn.execute(["ipv6 unicast-routing"])
                        conn.execute([f"ipv6 route {net_add}/{prefix} {next_hop}"])

                  elif choice == '3':
                        print("[INFO] Remove IPv4 Route")
                        net_add = input("Enter network address: ").strip()
                        while True:
                              try:
                                    check_valid_ipv4_address(net_add)
                                    break
                              except InvalidIPv4Address as e:
                                    print(e)
                                    net_add = input("Enter network address: ").strip()

                        netmask = input("Enter netmask: ").strip()
                        while not check_valid_netmask(netmask):
                              print(f"[ERROR] Invalid netmask: {netmask}")
                              netmask = input("Enter valid netmask: ").strip()

                        if not check_valid_ipv4_network(net_add, netmask):
                              print(f"[ERROR] Network address {net_add} is not valid for netmask {netmask}.")
                              continue

                        next_hop = input("Enter next hop: ").strip()
                        while True:
                              try:
                                    check_valid_ipv4_address(next_hop)
                                    break
                              except InvalidIPv4Address as e:
                                    print(e)
                                    next_hop = input("Enter next hop: ").strip()

                        conn.execute([f"no ip route {net_add} {netmask} {next_hop}"])

                  elif choice == '4':
                        print("[INFO] Remove IPv6 Route")
                        net_add = input("Enter network address: ").strip()
                        while not check_valid_ipv6_address(net_add):
                              print(f"[ERROR] Invalid network address: {net_add}")
                              net_add = input("Enter valid network address: ").strip()
                        while True:
                              try:
                                    prefix = input("Enter prefix: ").strip()
                                    prefix = int(prefix)

                                    if prefix < 0 or prefix > 128:
                                         break

                              except ValueError:
                                    pass

                              print(f"[ERROR] Invalid prefix: {prefix}")

                        next_hop = input("Enter next hop: ").strip()
                        while not check_valid_ipv6_address(next_hop):
                              print(f"[ERROR] Invalid next hop: {next_hop}")
                              next_hop = input("Enter valid next hop: ").strip()

                        while True:
                              try:
                                    check_valid_ipv6_address(next_hop)
                                    break
                              except Exception as e:
                                    print("e")
                                    next_hop = input("Enter next hop: ").strip()

                        ok, exit_if, _ = is_next_hop_direct_v4(conn, next_hop)

                        if not ok:
                              print(f"[ERROR] Next-hop {next_hop} is not configured in any direct connected networks.")
                              continue

                        conn.execute([f"no ipv6 route {net_add}/{prefix} {next_hop}"])

                  elif choice == '0':
                        print("[INFO] Exiting...")
                        break

                  else:
                        print(f"[ERROR] Invalid choice: {choice}")

      except Exception as e:
            print(f"[ERROR] Connection to {hostname} failed: {e}")
      finally:
            if conn:
                  conn.disconnect()
                  print(f'[INFO] Disconnected from {hostname}')


# === Cerinta 2b ===
def ping_test(source, destination):
      try:
            return source.execute(f"ping {destination}")
      except Exception as e:
            return print(f"[ERROR] Ping failed: {e}")

def ping_between_devices():
      '''
      - afiseaza toate deviceurile disponibile pentru ping
      - cere numele a 2 device-uri (sursa + destinatie)
      - stabileste conexiunea pe sursa
      - apeleaza ping intre ele
      - afiseaza rezultatul
      - incheie conexiunea
      '''
      elig = filter_devices(devices_data, required_cap="ping", roles={"router", "msw", "switch"})
      pingable = filter_devices(devices_data, required_cap="ping")
      if len(elig) < 1 or len(pingable) < 2:
            print("[ERROR] Not enough devices available for ping test.")
            return

      print_device_list(pingable, "Devices available for ping: ")
      print("!! PC devices cannot be used as source for ping !!")

      src = input("Select source device: ").strip()
      dest = input("Select destination device: ").strip()
      if src not in elig:
            print("[ERROR] Invalid source device choice. Please try again.")
            return
      if dest not in pingable:
            print("[ERROR] Invalid destination device choice. Please try again.")
            return
      if src == dest:
            print("[ERROR] Source and destination cannot be the same.")
            return

      src_dev = devices_data[src]
      dest_dev = devices_data[dest]
      if not (src_dev and dest_dev):
            print("[ERROR] Missing connection details for selected devices.")
            return

      dest_ip = dest_dev["connection"]["host"]
      if not dest_ip:
            print("[ERROR] Missing IP address for destination device.")
            return

      print(f"[INFO] Connecting to source device: {src} ...")
      conn = None
      try:
            conn = DeviceConnection(devices_data[src]['connection'])
            conn.connect()
            print(f"[INFO] Connected to {src}. Pinging {dest} ({dest_ip}) ...")
            result = ping_test(conn, dest_ip)
            print(f"[INFO] Ping result:\n{result}")
      except Exception as e:
            print(f"[ERROR] Connection to {src} failed: {e}")
      finally:
            if conn:
                  conn.disconnect()
                  print(f"[INFO] Disconnected from {src}.")


# === Cerinta 3a + optional 5 ===
def acl_standard_setup():
      while True:
            acl_name = input("Enter ACL name or number for NAT: ").strip()
            if is_valid_acl_name(acl_name):
                  break
            print("[ERROR] Invalid ACL name/number. Please try again.")

      is_numbered = acl_name.isdigit()
      acl_commands = []
      rules = []

      print("\nEnter ACL rules in one of the formats:")
      print("permit|deny any")
      print("permit|deny <ip> <wildcard>")
      print("Type 'done' to finish")

      if not is_numbered:
        acl_commands.append(f"ip access-list standard {acl_name}")

      while True:
            rule = input("> ").strip()
            if rule.lower() == 'done':
                  break

            tokens = rule.split()
            if len(tokens) not in (2, 3) or tokens[0] not in ("permit", "deny"):
                  print("[ERROR] Rule must be 'permit|deny any' or 'permit|deny <ip> <wildcard>'.")
                  continue

            if len(tokens) == 2:
                  if tokens[1].lower() != 'any':
                        print("[ERROR] Second token must be 'any' when only two tokens are used.")
                        continue
            else:
                  ip_part, wc_part = tokens[1], tokens[2]
                  try:
                        check_valid_ipv4_address(ip_part)
                  except InvalidIPv4Address as e:
                        print(e)
                        continue

                  if not check_valid_wildcard(wc_part):
                        print("[ERROR] Invalid wildcard mask in rule. Please try again.")
                        continue

            if is_numbered:
                  acl_commands.append(f"access-list {acl_name} {rule}")
            else:
                  acl_commands.append(rule)
            rules.append(rule)

      if not is_numbered:
            acl_commands.append("exit")

      warn_shadowing_standard(rules)

      return acl_commands, acl_name


def acl_extended_setup():
      while True:
            acl_name = input("Enter ACL name or number for NAT: ").strip()
            if is_valid_acl_name(acl_name, type="extended"):
                  break
            print("[ERROR] Invalid ACL name/number. Please try again.")

      is_numbered = acl_name.isdigit()
      acl_commands = []
      rules = []

      print("\nEnter ACL rules in one of the formats:")
      print("permit|deny <protocol> <src> [src-port] <dst> [dst-port] [established] [log]")
      print("Where <src> and <dst> can be 'any' or '<ip> <wildcard>'")
      print("Ports (only for tcp/udp) can be 'eq|ne|lt|gt <port>' OR 'range <start> <end>'")
      print("Type 'done' to finish")

      if not is_numbered:
            acl_commands.append(f"ip access-list extended {acl_name}")

      while True:
            rule = input("> ").strip()
            if rule.lower() == 'done':
                  break

            tokens = rule.split()
            if len(tokens) < 4:
                  print("[ERROR] Incomplete rule. Please provide at least 'permit|deny <protocol> <src> <dst>'.")
                  continue

            if tokens[0].lower() not in ("permit", "deny"):
                  print("[ERROR] Rule must start with 'permit|deny <protocol> <src> <dst>'.")
                  continue

            protocol = tokens[1].lower()
            supported = {"ip", "tcp", "udp", "icmp", "gre"}
            if protocol not in supported:
                  print(f"[ERROR] Unsupported protocol '{protocol}'. Supported: {', '.join(supported)}.")
                  continue

            idx = 2

            # --- Parse source ---
            t = tokens[idx].lower()
            if t == "any":
                  src = "any"
                  idx += 1
            elif t == "host":
                  if ((len(tokens) <= idx + 1) or not check_valid_ipv4_address(tokens[idx + 1])):
                        print("[ERROR] Invalid host IP address for source.")
                        continue
                  src = f"host {tokens[idx + 1]}"
                  idx += 2
            else:
                  if ((len(tokens) <= idx + 1) or not check_valid_ipv4_address(tokens[idx]) or not check_valid_wildcard(tokens[idx + 1])):
                        print("[ERROR] Invalid <ip> <wildcard> for source.")
                        continue
                  src = f"{tokens[idx]} {tokens[idx + 1]}"
                  idx += 2

            # --- Parse optional source port ---
            src_port = None
            if protocol in {"tcp", "udp"} and idx < len(tokens) and tokens[idx].lower() in {"eq", "ne", "lt", "gt", "range"}:
                  if tokens[idx].lower() == "range":
                        if len(tokens) <= idx + 2 or not (is_valid_port_number(tokens[idx+1]) and is_valid_port_number(tokens[idx+2])):
                              print("[ERROR] Invalid range ports (0 - 65535).")
                              continue
                        src_port = f"range {tokens[idx + 1]} {tokens[idx + 2]}"
                        idx += 3

                  else:
                        if len(tokens) <= idx + 1 or not is_valid_port_number(tokens[idx+1]):
                              print("[ERROR] A valid numeric port (0 - 65535) is required after operator.")
                              continue
                        src_port = f"{tokens[idx].lower()} {tokens[idx + 1]}"
                        idx += 2

            elif protocol not in {"tcp", "udp"} and idx < len(tokens) and tokens[idx].lower() in {"eq", "ne", "lt", "gt", "range"}:
                  print(f"[ERROR] Source port not applicable for protocol '{protocol}'.")
                  continue

            # --- Parse destination ---
            if idx >= len(tokens):
                  print("[ERROR] Missing destination address.")
                  continue

            t = tokens[idx].lower()
            if t == "any":
                  dst = "any"
                  idx += 1
            elif t == "host":
                  if ((len(tokens) <= idx + 1) or not check_valid_ipv4_address(tokens[idx + 1])):
                        print("[ERROR] Invalid host IP address for destination.")
                        continue
                  dst = f"host {tokens[idx + 1]}"
                  idx += 2
            else:
                  if ((len(tokens) <= idx + 1) or not check_valid_ipv4_address(tokens[idx]) or not check_valid_wildcard(tokens[idx + 1])):
                        print("[ERROR] Invalid <ip> <wildcard> for destination.")
                        continue
                  dst = f"{tokens[idx]} {tokens[idx + 1]}"
                  idx += 2

            # --- Parse optional destination port ---
            dst_port = None
            if protocol in {"tcp", "udp"} and idx < len(tokens) and tokens[idx].lower() in {"eq", "ne", "lt", "gt", "range"}:
                  if tokens[idx].lower() == "range":
                        if len(tokens) <= idx + 2 or not (tokens[idx + 1].isdigit() and tokens[idx + 2].isdigit()):
                              print("[ERROR] Invalid range ports.")
                              continue
                        dst_port = f"range {tokens[idx + 1]} {tokens[idx + 2]}"
                        idx += 3

                  else:
                        if len(tokens) <= idx + 1 or not tokens[idx + 1].isdigit():
                              print("[ERROR] A valid port value required after operator.")
                              continue
                        dst_port = f"{tokens[idx].lower()} {tokens[idx + 1]}"
                        idx += 2

            elif protocol not in {"tcp", "udp"} and idx < len(tokens) and tokens[idx].lower() in {"eq", "ne", "lt", "gt", "range"}:
                  print(f"[ERROR] Destination port not applicable for protocol '{protocol}'.")
                  continue

            # --- Parse optional established and log ---
            established = False
            if idx < len(tokens) and tokens[idx].lower() == "established":
                  if protocol != "tcp":
                        print("[ERROR] 'established' is only valid with TCP protocol.")
                        continue
                  established = True
                  idx += 1

            log = False
            if idx < len(tokens) and tokens[idx].lower() == "log":
                  log = True
                  idx += 1

            if idx != len(tokens):
                  print("[ERROR] Extra tokens found at the end of the rule.")
                  continue

            rule_parts = [tokens[0], protocol, src]
            if src_port:
                  rule_parts.append(src_port)
            rule_parts.append(dst)
            if dst_port:
                  rule_parts.append(dst_port)
            if established:
                  rule_parts.append("established")
            if log:
                  rule_parts.append("log")
            final_rule = " ".join(rule_parts)

            if is_numbered:
                  acl_commands.append(f"access-list {acl_name} {final_rule}")
            else:
                  acl_commands.append(final_rule)

            rules.append(final_rule)

      if not is_numbered:
            acl_commands.append("exit")

      warn_shadowing_extended(rules)

      return acl_commands, acl_name


def acl_remove(conn, type="standard"):
      while True:
            acl_name = input("Enter ACL name or number to remove: ").strip()
            if is_valid_acl_name(acl_name, type=type):
                  break
            print("[ERROR] Invalid ACL name/number. Please try again.")

      confirm = input(f"Are you sure you want to remove ACL '{acl_name}'? (y/n): ").strip().lower()
      if confirm not in ("y", "yes", "YES", "Y"):
            print("[INFO] ACL removal cancelled.")
            return None, None

      try:
            show_out = conn.execute("show ip access-lists")
      except Exception as e:
            print(f"[ERROR] Could not run 'show ip access-lists': {e}")
            return None, None

      if not acl_exists_in_show(show_out, type, acl_name):
            print(f"[WARN] {type.capitalize()} ACL '{acl_name}' not found on device.")
            return None, None

      if acl_name.isdigit():
            remove_cmd = [f"no access-list {acl_name}"]
      else:
            remove_cmd = [f"no ip access-list {type} {acl_name}"]

      return remove_cmd, acl_name


def show_acls(hostname):
    conn = None
    try:
        conn = DeviceConnection(devices_data[hostname]['connection'])
        conn.connect()
        txt = conn.execute("show ip access-lists")
        header_re = re.compile(r'^\s*(Standard|Extended)\s+IP\s+access\s+list\s+(\S+)', re.I)
        entry_re  = re.compile(r'^\s*(\d+)\s+(.*\S)\s*$')
        current = None

        print(f"\n[INFO] Access Lists on {hostname}:")
        for line in txt.splitlines():
            h = header_re.match(line)
            if h:
                if current is not None:
                    print()
                current = (h.group(1).capitalize(), h.group(2))
                print(f"{current[0]} ACL {current[1]}")
                continue
            e = entry_re.match(line)
            if e:
                print(f"  {e.group(1):>4}  {e.group(2)}")

    except Exception as e:
        print(f"[ERROR] Could not fetch ACLs: {e}")

    finally:
        if conn:
            conn.disconnect()


def acl_configuration(hostname):
      '''
      - meniu alegeri: ACL standard / extended
      - ip access-list {{standard | extended} {access-list-name access-list-number}}
      Extra: stergere acl: no ip access-list {{standard | extended} {access-list-name access-list-number}}
      '''
      print("\n============= OPTIONS =============")
      print("1. Add ACL Standard")
      print("2. Add ACL Extended")
      print("3. Remove ACL Standard")
      print("4. Remove ACL Extended")
      print("5. Apply ACL")
      print("6. Show ACLs")
      print("0. Exit")
      print("===================================\n")

      nat_choice = input("Select ACL choice: ").strip()
      if nat_choice not in {'1', '2', '3', '4', '5', '6', '0'}:
            print("[ERROR] Invalid ACL choice. Please try again.")
            return

      conn = None
      try:
            conn = DeviceConnection(devices_data[hostname]['connection'])
            conn.connect()
            print(f"[INFO] Connected to {hostname}.")

            if nat_choice in {'1', '2'}:
                  is_standard = (nat_choice == '1')
                  acl_commands, acl_name = acl_standard_setup() if is_standard else acl_extended_setup()

                  print("[INFO] Applying ACL configuration ...")
                  conn.execute(acl_commands)
                  print("[INFO] ACL configuration applied successfully.")

            elif nat_choice in {'3', '4'}:
                  type = "standard" if nat_choice == '3' else "extended"

                  remove_cmd, acl_name = acl_remove(conn, type=type)
                  if remove_cmd is None:
                        return

                  conn.execute(remove_cmd)
                  print(f"[INFO] ACL '{acl_name}' removed successfully.")

            elif nat_choice == '5':
                  print("Available interfaces:")
                  interfaces = conn.execute("show ip interface brief | include (up|down)")
                  print(interfaces)
                  interface = input("Select interface: ").strip()
                  while interface not in interfaces:
                        print("[ERROR] Invalid interface choice. Please try again.")
                  interface = input("Select interface: ").strip()
                  show_acls(hostname)
                  acl_name = input("Select ACL name or number: ").strip()
                  rule = input("Select in / out: ")
                  while rule not in {"in", "out"}:
                        print("[ERROR] Invalid rule choice. Please try again.")
                  conn.execute([
                      f"interface {interface}",
                      f"ip access-group {acl_name} {rule}",
                      "exit"
                  ])

                  return

            elif nat_choice == '6':
                  show_acls(hostname)
                  return

            else:
                  print("[INFO] Exiting...")
                  return

      except Exception as e:
            print(f"[ERROR] Connection to {hostname} failed: {e}")

      finally:
            if conn:
                  conn.disconnect()
                  print(f"[INFO] Disconnected from {hostname}.")


# === Cerinta 4a ===
def backup(hostname):
      conn = None
      try:
            conn = DeviceConnection(devices_data[hostname]['connection'])
            conn.connect()

            backup_dir = "backup"
            if not os.path.exists(backup_dir):
                  os.makedirs(backup_dir)
                  print(f"[INFO] Created backup directory: {backup_dir}")

            filename = f"{hostname}_backup.txt"
            backup_path = os.path.join(backup_dir, filename)

            config = conn.execute("show running-config")

            if not config:
                  print(f"[ERROR] No configuration data retrieved from {hostname}.")
                  return

            with open(backup_path, 'w') as file:
                  file.write(config)

            print(f"[INFO] Backup saved as {filename} to {backup_dir} directory.")

      except Exception as e:
            print(f"[ERROR] Connection to {hostname} failed: {e}")
      finally:
            if conn:
                  conn.disconnect()


def save_backup():
      '''
      - stabilire conexiune hostname
      - salveaza configuratia in folderul backup (optiune folder default), cu denumirea default device_backup.txt
      - salveaza show running-config
      - include verificari pentru lucrul cu foldere si fisiere
      - incheiere conexiune hostname
      '''
      print("\n============= OPTIONS =============")
      print("1. Backup a specific device")
      print("2. Backup all devices")
      print("0. Exit")
      print("===================================\n")

      choice = input("Select option: ").strip()
      if choice not in {'1', '2', '0'}:
            print("[ERROR] Invalid choice. Please try again.")
            return

      elig = filter_devices(devices_data, required_cap="backup", roles={"router", "switch", "msw"})

      if choice == '1':
            print_device_list(elig, "Devices eligible for backup: ")
            dev = pick_from_list(elig)
            if dev:
                  backup(dev)

      elif choice == '2':
            for device in elig:
                  backup(device)

            print(f"\n[INFO] Full backup completed!")

      else:
            print("[INFO] Exiting...")
            return


# === Cerinta optional 1 ===
def ipv6_config(hostname):
      '''
      - stabilire conexiune hostname
      - afiseaza interfetele disponibile / vlan
      - permite alegerea unei interfete / vlan
      - cere o adresa ipv6 si verifica daca este valida
      - include ipv6 default gateway (SW)
      - incheiere conexiune hostname
      '''
      conn = None
      try:
            conn = DeviceConnection(devices_data[hostname]['connection'])
            conn.connect()
            print(f"[INFO] Connected to {hostname}.")

            print("Available interfaces:")
            interfaces = conn.execute("show ipv6 interface brief | include (up|down)")
            print(interfaces)
            interface = input("Select interface: ").strip()
            while interface not in interfaces:
                  print("[ERROR] Invalid interface choice. Please try again.")
                  interface = input("Select interface: ").strip()

            print("\n============= OPTIONS =============")
            print("1. Manual")
            print("2. EUI-64 (with network address)")
            print("0. Exit")
            print("===================================\n")
            choice = input("Select option: ").strip()
            if choice not in {'1', '2', '0'}:
                  print("[ERROR] Invalid choice. Please try again.")
                  return

            if choice == '0':
                  print("[INFO] Exiting...")
                  return

            commands = [f"interface {interface}"]

            if choice == '1':
                  print("\n============= OPTIONS =============")
                  print("1. GUA")
                  print("2. Link-local")
                  print("0. Exit")
                  print("===================================\n")
                  ch = input("Select option: ").strip()
                  if ch not in {'1', '2', '0'}:
                        print("[ERROR] Invalid choice. Please try again.")
                        return

                  if ch == '0':
                        print("[INFO] Exiting...")
                        return

                  ipv6_address = input("Enter IPv6 address: ").strip()
                  while not check_valid_ipv6_address(ipv6_address) or (ch == '2' and not ipv6_address.startswith('fe80')):
                        print("[ERROR] Invalid IPv6 address. Please try again.")
                        ipv6_address = input("Enter IPv6 address: ").strip()

                  if ch == '1':
                        ipv6_prefix = input("Enter IPv6 prefix: ").strip()
                        ipv6_prefix = int(ipv6_prefix)
                        while ipv6_prefix < 0 or ipv6_prefix > 128:
                              print("[ERROR] Invalid IPv6 prefix. Please try again.")
                              ipv6_prefix = input("Enter IPv6 prefix: ").strip()
                              ipv6_prefix = int(ipv6_prefix)

                  if ch == '1':
                              commands.append(f"ipv6 address {ipv6_address}/{ipv6_prefix}")
                  elif ch == '2':
                              commands.append(f"ipv6 address {ipv6_address} link-local")

            elif choice == '2':
                  ipv6_address = input("Enter IPv6 address: ").strip()
                  while not check_valid_ipv6_address(ipv6_address):
                        print("[ERROR] Invalid IPv6 address. Please try again.")
                        ipv6_address = input("Enter IPv6 address: ").strip()

                  ipv6_prefix = input("Enter IPv6 prefix: ").strip()
                  ipv6_prefix = int(ipv6_prefix)
                  while ipv6_prefix < 0 or ipv6_prefix > 128:
                        print("[ERROR] Invalid IPv6 prefix. Please try again.")
                        ipv6_prefix = input("Enter IPv6 prefix: ").strip()
                        ipv6_prefix = int(ipv6_prefix)

                  commands.append(f"ipv6 address {ipv6_address}/{ipv6_prefix} eui-64")


            commands.append("no sh")
            commands.append("exit")

            device_role = devices_data[hostname]['role']
            if device_role in ['router', 'msw']:
                  commands.insert(0, 'ipv6 unicast-routing')

            if device_role == 'switch':
                  ans = input('Do you want to set a default gateway? (y/n)').strip()
                  if ans.lower() in ['y', 'yes', 'ye']:
                        default_gateway = input('Enter default gateway: ').strip()
                        while not check_valid_ipv6_address(default_gateway):
                              print("[ERROR] Invalid IPv6 address. Please try again.")
                              default_gateway = input("Enter default gateway: ").strip()

                        commands.append(f"ipv6 route ::/0 {default_gateway}")

            conn.execute(commands)
            print("[INFO] IPv6 configuration applied successfully.")

      except Exception as e:
            print(f"[ERROR] Connection to {hostname} failed: {e}")

      finally:
            if conn:
                  conn.disconnect()
                  print(f"[INFO] Disconnected from {hostname}.")


# Cerinta optional 3 ===
def ping_all_test():
      '''
      - stabilire conexiune un device (R, MSW, SW)
      - incearca ping la toate deviceurile existente
      - afisare rezultate
      - incheiere conexiune device
      - reluare pasi cu un alt device
      '''
      sources = filter_devices(devices_data, required_cap="ping", roles={"router", "switch", "msw"})
      targets = filter_devices(devices_data, required_cap="ping")
      if len(sources) < 1 or len(targets) < 2:
            print("[ERROR] Not enough devices for ping testing.")
            return

      for src in sources:
            print(f"\n[INFO] Connecting to source device: {src}")
            conn = None
            try:
                  conn = DeviceConnection(devices_data[src]['connection'])
                  conn.connect()
                  print(f"[INFO] Connected to {src}. Pinging all devices ...")
                  for dest in targets:
                        if src == dest:
                              continue
                        dest_dev = devices_data[dest]
                        if not dest_dev:
                              print(f"[WARNING] Missing connection details for {dest}. Skipping.")
                              continue
                        dest_ip = dest_dev["connection"]["host"]
                        if not dest_ip:
                              print(f"[WARNING] Missing IP address for {dest}. Skipping.")
                              continue
                        print(f"[INFO] Pinging {dest} ({dest_ip}) ...")
                        try:
                              result = ping_test(conn, dest_ip)
                              print(f"[INFO] Ping result to {dest}:\n{result}")
                        except Exception as e:
                              print(f"[ERROR] Ping to {dest} failed: {e}")
            except Exception as e:
                  print(f"[ERROR] Connection to {src} failed: {e}")
            finally:
                  if conn:
                        conn.disconnect()
                        print(f"[INFO] Disconnected from {src}.")


# === Cerinta optional 4 ===
def dhcp_config(hostname):
      '''
      - conexiune hostname
      - alegere adrese ip excluse (single sau range)
      - permite creare pool-uri cu name, network, mask, default-router, dns, domain, lease
      - aplicare comenzi pe device
      - incheiere conexiune hostname
      '''

      cmds = ["service dhcp"]

      # ---- Excluded addresses ----
      print("\n=== DHCP: Excluded addresses ===")
      print("Enter a single IP (e.g., 192.168.1.1) or a range (e.g., 192.168.1.10 192.168.1.50).")
      print("Press Enter to continue.")
      excluded_ranges_int = []

      while True:
            ans = input("> ").strip()
            if ans == "":
                  break
            parts = ans.split()
            if len(parts) == 1:
                  addr = parts[0]
                  try:
                        check_valid_ipv4_address(addr)
                  except InvalidIPv4Address as e:
                        print(e)
                        continue
                  cmds.append(f"ip dhcp excluded-address {addr}")
                  addr_int = ip_to_int(addr)
                  excluded_ranges_int.append((addr_int, addr_int))
            elif len(parts) == 2:
                  start, stop = parts
                  try:
                        check_valid_ipv4_address(start)
                        check_valid_ipv4_address(stop)
                  except InvalidIPv4Address as e:
                        print(e)
                        continue
                  start_int = ip_to_int(start)
                  stop_int = ip_to_int(stop)
                  if start_int > stop_int:
                        print("[ERROR] Range must be in ascending order: <start> <end>.")
                        continue
                  cmds.append(f"ip dhcp excluded-address {start} {stop}")
                  excluded_ranges_int.append((start_int, stop_int))
            else:
                  print("[ERROR] Invalid format.")

      # ---- Pools ----
      print("\n=== DHCP: Pools ===")
      print("Press Enter to continue.")
      pools = []
      staged = []

      while True:
            name = input("Pool name: ").strip()
            if name == "":
                  break
            if not is_valid_pool_name(name):
                  print("[ERROR] Invalid pool name.")
                  continue
            if any(p[0] == name for p in pools):
                  print(f"[ERROR] Pool '{name}' already defined in this session.")
                  continue
            net = input("Network (e.g. 192.168.10.0): ").strip()
            mask = input("Mask (e.g. 255.255.255.0): ").strip()

            try:
                  check_valid_ipv4_address(net)
            except InvalidIPv4Address  as e:
                  print(e)
                  continue

            if not check_valid_netmask(mask):
                  continue

            if not check_valid_ipv4_network(net, mask):
                  print("[ERROR] The IP provided is NOT the network address for this mask.")
                  continue

            conflict = next((nm for (n2, m2, nm) in staged if subnets_overlaps(net, mask, n2, m2)), None)
            if conflict:
                  print(f"[ERROR] Subnet overlaps with pool '{conflict}'.")
                  continue

            gw = input("Default-router: ").strip()
            try:
                  check_valid_ipv4_address(gw)
            except InvalidIPv4Address as e:
                  print(e); continue

            if not ip_in_network(gw, net, mask):
                  print("[ERROR] Default-router must be inside the subnet.")
                  continue

            gw_i = ip_to_int(gw)

            if any(start <= gw_i <= stop for (start, stop) in excluded_ranges_int):
                  print("[WARNING] Gateway falls inside an excluded-address range.")

            # DNS servers (optional)
            dns_raw = input("DNS server(s) (space separated; empty = none): ").strip()
            dns_list = []
            if dns_raw:
                  ok = True
                  for tok in dns_raw.split():
                        try:
                              check_valid_ipv4_address(tok)
                        except InvalidIPv4Address as e:
                              print(e)
                              ok = False
                              break
                        dns_list.append(tok)
                  if not ok:
                        continue

            # Domain (optional)
            domain = input("Domain name (empty = none): ").strip()
            if " " in domain:
                  print("[ERROR] Domain name cannot contain spaces.")
                  continue

            # Lease (optional)
            lease_str = input("Lease (e.g., '3 12 0' for 3d12h; empty = default): ").strip()
            lease = None
            if lease_str:
                  parts = lease_str.split()
                  if not all(p.isdigit() for p in parts) or len(parts) > 3:
                        print("[ERROR] Lease must be 'days [hours [minutes]]'.")
                        continue

                  d = int(parts[0]); h = int(parts[1]) if len(parts) > 1 else None
                  m = int(parts[2]) if len(parts) > 2 else None

                  if (h is not None and not (0 <= h <= 23)) or (m is not None and not (0 <= m <= 59)):
                        print("[ERROR] Hours must be 0–23 and minutes 0–59.")
                        continue

                  lease = (d, h, m)

            pools.append((name, net, mask, gw, dns_list, domain, lease))
            staged.append((net, mask, name))
            print(f" [+] pool {name} staged")

      if not pools and len(cmds) == 1:
            print("[INFO] Nothing to configure.")
            return []

      # ---- Commands ----
      for (name, net, mask, gw, dns_list, domain, lease) in pools:
            cmds.append(f"ip dhcp pool {name}")
            cmds.append(f"network {net} {mask}")
            cmds.append(f"default-router {gw}")
            if dns_list:
                  cmds.append("dns-server " + " ".join(dns_list))
            if domain:
                  cmds.append(f"domain-name {domain}")
            if lease:
                  d, h, m = lease
                  if h is None:
                        cmds.append(f"lease {d}")
                  elif m is None:
                        cmds.append(f"lease {d} {h}")
                  else:
                        cmds.append(f"lease {d} {h} {m}")
            cmds.append(" exit")

      conn = None
      try:
            conn = DeviceConnection(devices_data[hostname]['connection'])
            conn.connect()
            print(f"[INFO] Connected to {hostname}.")
            conn.execute(cmds)
            print("[INFO] DHCP configuration applied.")

      except Exception as e:
            print(f"[ERROR] DHCP configuration failed on {hostname}: {e}")

      finally:
            if conn:
                  conn.disconnect()
                  print(f"[INFO] Disconnected from {hostname}.")

      return cmds

# === Cerinta optional 6 ===
def nat_config(hostname, debug=False):
      '''
      - meniu alegeri: NAT static / dinamic / pat
      - conexiune hostname
      - alegere nume ACL
      - afiseaza interfetele
      - alegere interfete de inside
      - alegere interfete de outside
      - ip nat inside source list <acl> interface <outside> overload
      - incheiere conexiune hostname
      '''
      print("\n============= OPTIONS =============")
      print("1. NAT Static")
      print("2. NAT Dinamic")
      print("3. NAT PAT")
      print("===================================\n")

      nat_choice = input("Select NAT type: ").strip()
      if nat_choice not in {'1', '2', '3'}:
            print("[ERROR] Invalid NAT choice. Please try again.")
            return

      conn = None
      try:
            conn = DeviceConnection(devices_data[hostname]['connection'])
            conn.connect()
            print(f"[INFO] Connected to {hostname}.")

            interfaces = devices_data[hostname]['interfaces'] or {}
            if not interfaces:
                  print("[ERROR] No interfaces data available.")
                  return

            print("Available interfaces:")
            for if_name in interfaces.keys():
                  print(f"  - {if_name}")

            while True:
                  user_input = input("Select INSIDE interface: ").strip()
                  inside_if = get_interface_from_input(user_input, interfaces)
                  if inside_if:
                        break
                  print("[ERROR] Invalid interface choice. Please try again.")

            while True:
                  user_input = input("Select OUTSIDE interface: ").strip()
                  outside_if = get_interface_from_input(user_input, interfaces)
                  if outside_if and outside_if != inside_if:
                        break
                  print("[ERROR] Invalid interface choice. Please try again.")

            if debug == False:
                  conn.execute([
                  f"interface {inside_if}",
                  "ip nat inside",
                  "exit",
                  f"interface {outside_if}",
                  "ip nat outside",
                  "exit"
                  ])

            # === NAT configuration ===
            nat_config_cmds = []
            acl_cmds = []
            acl_name = None

            # ---------- Static NAT ----------
            if nat_choice == '1':
                  print("[INFO] Configuring Static NAT ...")
                  inside_ip = input("Private (inside local) IP: ").strip()
                  try:
                        check_valid_ipv4_address(inside_ip)
                  except InvalidIPv4Address as e:
                        print(e)
                        return

                  inside_net_ip = devices_data[hostname]["interfaces"][inside_if]["ip_address"]
                  inside_net_mask = devices_data[hostname]["interfaces"][inside_if]["netmask"]

                  if not ip_in_network(inside_ip, inside_net_ip, inside_net_mask):
                        print(f"[ERROR] {inside_ip} does not belong to the network {inside_net_ip}/{inside_net_mask} on {inside_if}")
                        return

                  public_ip = input("Public (inside global) IP: ").strip()
                  try:
                        check_valid_ipv4_address(public_ip)
                  except InvalidIPv4Address as e:
                        print(e)
                        return

                  outside_net_ip = devices_data[hostname]["interfaces"][outside_if]["ip_address"]
                  outside_net_mask = devices_data[hostname]["interfaces"][outside_if]["netmask"]

                  if not ip_in_network(public_ip, outside_net_ip, outside_net_mask):
                        print(f"[ERROR] {public_ip} does not belong to the network {outside_net_ip}/{outside_net_mask} on {outside_if}")
                        return

                  nat_config_cmds.append(f"ip nat inside source static {inside_ip} {public_ip}")

            # ---------- Dynamic NAT ----------
            elif nat_choice == '2':
                  print("[INFO] Configuring Dynamic NAT ...")
                  invalids = []
                  pool_name = input("Enter NAT pool name: ").strip()
                  if not is_valid_pool_name(pool_name):
                        print(f"[ERROR] Invalid NAT pool name '{pool_name}'. Use only letters, digits, and underscores.")
                        return

                  start_ip = input("Start IP of NAT pool: ").strip()
                  if not check_valid_ipv4_address(start_ip):
                        invalids.append(f"Start IP: {start_ip}")

                  end_ip = input("End IP of NAT pool: ").strip()
                  if not check_valid_ipv4_address(end_ip):
                        invalids.append(f"End IP: {end_ip}")

                  if ip_to_int(start_ip) > ip_to_int(end_ip):
                        print(f"[ERROR] Start IP {start_ip} must be less than End IP {end_ip}.")
                        return

                  netmask = input("Netmask for NAT pool: ").strip()
                  if not check_valid_netmask(netmask):
                        invalids.append(f"Netmask: {netmask}")

                  if invalids:
                        print(f"[ERROR] Invalid IP(s): {', '.join(invalids)}")
                        return

                  if ip_to_int(start_ip) > ip_to_int(end_ip):
                        print(f"[ERROR] Start IP {start_ip} must be less than End IP {end_ip}.")
                        return

                  # Check if pool IPs overlap with outside interface network
                  outside_net_ip = devices_data[hostname]["interfaces"][outside_if]["ip_address"]
                  outside_net_mask = devices_data[hostname]["interfaces"][outside_if]["netmask"]

                  if not (ip_in_network(start_ip, outside_net_ip, outside_net_mask) and ip_in_network(end_ip, outside_net_ip, outside_net_mask)):
                        print(f"[ERROR] NAT pool {start_ip}-{end_ip}/{netmask} does not match outside network "f"{outside_net_ip}/{outside_net_mask} on {outside_if}.")
                        return

                  acl_cmds, acl_name = acl_standard_setup()

                  nat_config_cmds.append(f"ip nat pool {pool_name} {start_ip} {end_ip} netmask {netmask}")
                  nat_config_cmds.append(f"ip nat inside source list {acl_name} pool {pool_name}")

            # ---------- PAT NAT ----------
            elif nat_choice == '3':
                  print("[INFO] Configuring NAT PAT ...")
                  acl_cmds, acl_name = acl_standard_setup()
                  nat_config_cmds.append(f"ip nat inside source list {acl_name} interface {outside_if} overload")

            if acl_cmds:
                  print("[INFO] Applying ACL configuration ...")
                  if debug == False:
                        conn.execute(acl_cmds)
                  else:
                        print("\n".join(acl_cmds))
                  print("[INFO] ACL configuration applied successfully.")

            if nat_config_cmds:
                  print("[INFO] Applying NAT configuration ...")
                  if debug == False:
                        conn.execute(nat_config_cmds)
                  else:
                        print("\n".join(nat_config_cmds))

            print("[INFO] NAT configuration applied successfully.")

      except Exception as e:
            print(f"[ERROR] Connection to {hostname} failed: {e}")

      finally:
            if conn:
                  conn.disconnect()
                  print(f"[INFO] Disconnected from {hostname}.")


# === Cerinta optional 7 ===
def show_config_differences(hostname):
      '''
      - conexiune hostname
      - afiseaza diferenta intre running-config si ultimul backup-local
      - daca nu exista backup local, compara running-config cu startup-config
      - include validari pentru lucrul cu foldere si fisiere
      - incheiere conexiune hostname
      '''
      conn = None
      try:
            conn = DeviceConnection(devices_data[hostname]['connection'])
            conn.connect()
            print(f"[INFO] Connected to {hostname}.")

            device_info = devices_data[hostname]
            backup_dir = 'backup'
            backup_path = os.path.join(backup_dir, f"{hostname}_backup.txt")

            running_config = conn.execute("show running-config")

            if os.path.exists(backup_dir) and os.path.exists(backup_path):
                  with open(backup_path, 'r') as f:
                      backup_config = f.read()

                  diff = difflib.unified_diff(
                      backup_config.splitlines(keepends=True),
                      running_config.splitlines(keepends=True),
                      fromfile='Backup',
                      tofile='Running'
                  )

                  diff_output = "".join(diff)

                  if diff_output:
                      print(f"[INFO] Differences between backup and running-config on {hostname}:")
                      print(diff_output)
                  else:
                      print(f"[INFO] No differences found between backup and running-config on {hostname}.")
            else:
                  print(f"[INFO] No backup found for {hostname}. Comparing running-config with startup-config.")
                  startup_config = conn.execute("show startup-config")

                  diff = difflib.unified_diff(
                      startup_config.splitlines(keepends=True),
                      running_config.splitlines(keepends=True),
                      fromfile='Startup',
                      tofile='Running'
                  )

                  diff_output = "".join(diff)

                  if diff_output:
                      print(f"[INFO] Differences between startup-config and running-config on {hostname}:")
                      print(diff_output)
                  else:
                      print(f"[INFO] No differences found between startup-config and running-config on {hostname}.")

      except Exception as e:
            print(f"[ERROR] Connection to {hostname} failed: {e}")

      finally:
            if conn:
                  conn.disconnect()
                  print(f"[INFO] Disconnected from {hostname}.")


def save_config_on_device(hostname):
      '''
      - stabileste conexiunea
      - do wr
      - incheiere conexiunea hostname
      '''
      confirm = input(f"Do you want to save the running config on {hostname}? (y/n): ").strip().lower()
      if confirm not in ("y", "yes", "YES", "Y"):
            print("[INFO] Save operation cancelled.")
            return

      conn = None
      try:
            conn = DeviceConnection(devices_data[hostname]['connection'])
            conn.connect()
            conn.execute(["do write"])
            print(f"[INFO] Configuration saved successfully on {hostname}.")

      except Exception as e:
            print(f"[ERROR] Connection to {hostname} failed: {e}")
      finally:
            if conn:
                  conn.disconnect()
                  print(f"[INFO] Disconnected from {hostname}.")


# === Meniu ===
def interactive_menu():
      if not devices_data:
            print("[ERROR] No devices data available. Exiting menu...")
            return
      while True:
            print("\n===================================")
            print("===== NETWORK AUTOMATION MENU =====")
            print("===================================")
            print("1. Configure VLANs")
            print("2. Configure static routing")
            print("3. Test connectivity (ping)")
            print("4. Configure ACL")
            print("5. Configure IPv6")
            print("6. Configure DHCP")
            print("7. Configure NAT")
            print("8. Save configuration on devices")
            print("9. Compare configurations")
            print("10. Save backup of configurations")
            print("0. Exit")
            print("===================================\n")

            choice = input("Enter your choice: ").strip()

            if choice == '1':
                  elig = filter_devices(devices_data, required_cap="vlan", roles={"router", "switch", "msw"})
                  print_device_list(elig, "Devices eligible for VLAN config: ")
                  dev = pick_from_list(elig)
                  if dev:
                        basic_vlan_config(dev)

            elif choice == '2':
                  elig = filter_devices(devices_data, required_cap="routing", roles={"router", "msw"})
                  print_device_list(elig, "Devices eligible for static routing: ")
                  dev = pick_from_list(elig)
                  if dev:
                        static_routing(dev)

            elif choice == '3':
                  print("Available options:")
                  print("1. Ping between two specific devices")
                  print("2. Ping between all devices")
                  ping_choice = input("Select an option: ").strip()
                  if ping_choice == '1':
                        ping_between_devices()
                  elif ping_choice == '2':
                        ping_all_test()
                  else:
                        print("[ERROR] Invalid choice. Please try again.")

            elif choice == '4':
                  elig = filter_devices(devices_data, required_cap="acl", roles={"router", "switch", "msw"})
                  print_device_list(elig, "Devices eligible for ACL: ")
                  dev = pick_from_list(elig)
                  if dev:
                        acl_configuration(dev)

            elif choice == '5':
                  elig = filter_devices(devices_data, required_cap="ipv6")
                  print_device_list(elig, "Devices eligible for IPv6: ")
                  dev = pick_from_list(elig)
                  if dev:
                        ipv6_config(dev)

            elif choice == '6':
                  elig = filter_devices(devices_data, required_cap="dhcp", roles={"router", "msw"})
                  print_device_list(elig, "Devices eligible for DHCP:")
                  dev = pick_from_list(elig)
                  if dev:
                        dhcp_config(dev)

            elif choice == '7':
                  elig = filter_devices(devices_data, required_cap="nat", roles={"router"})
                  print_device_list(elig, "Devices eligible for NAT: ")
                  dev = pick_from_list(elig)
                  if dev:
                        nat_config(dev)

            elif choice == '8':
                  elig = filter_devices(devices_data, required_cap="save", roles={"router", "switch", "msw"})
                  print_device_list(elig, "Devices eligible to save config: ")
                  dev = pick_from_list(elig)
                  if dev:
                        save_config_on_device(dev)

            elif choice == '9':
                  elig = filter_devices(devices_data, required_cap="compare")
                  print_device_list(elig, "Devices eligible for config diff: ")
                  dev = pick_from_list(elig)
                  if dev:
                        show_config_differences(dev)

            elif choice == '10':
                  save_backup()

            elif choice == '0':
                  print("Exiting menu...")
                  break
            else:
                  print("[ERROR] Invalid choice. Please try again.")


if __name__ == "__main__":
    interactive_menu()