import re
from exceptions import *

def check_valid_ipv4_address(ip_address):
      '''
      Verifica daca o adresa IP este valida:
      IPv4:
      - are 4 campuri separate prin .
      - fiecare camp este un numar intre 0 si 255
      - nu contine litere sau caractere speciale
      '''
      parts = ip_address.split('.')
      if len(parts) != 4:
            raise InvalidFormat(f"[ERROR] Adresa trebuie să conțină exact 4 câmpuri: {ip_address}")

      for part in parts:
        if not part.isdigit():
            raise NonNumericField(f"[ERROR] Câmpul '{part}' nu este numeric.")
        num = int(part)
        if num < 0 or num > 255:
            raise OutOfRangeField(f"[ERROR] Câmpul '{part}' nu este între 0 și 255.")
        if part != str(num):
            raise LeadingZeroField(f"[ERROR] Câmpul '{part}' conține zerouri la început.")

      return True


def check_valid_ipv6_address(ip_address):
      '''
      Verifica daca o adresa IP este valida:
      IPv6:
      - are 8 campuri separate prin :
      - fiecare camp are cate 4 fielduri
      - daca nu are 8 campuri, verifica sa aiba :: si doar o singura data
      - fiecare field este un numar intre 0 si f
      - nu contine alte litere (doar a-f si A-F) sau caractere speciale
      '''
      if ip_address.count('::') > 1:
          return False

      if '::' in ip_address:
            parts = ip_address.split('::')

            if len(parts) > 2:
                  return False

            first_part = parts[0].split(':') if parts[0] else []
            second_part = parts[1].split(':') if parts[1] else []

            if len(first_part) + len(second_part) > 7:
                  return False

            for part in first_part + second_part:
                  if not is_valid_ipv6_segment(part):
                        return False

      else:
            parts = ip_address.split(':')
            if len(parts) != 8:
                  return False

            for part in parts:
                  if not is_valid_ipv6_segment(part):
                        return False

      return True


def is_valid_ipv6_segment(segment):
      """
      Verifica daca un segment al unei adrese IPv6 este valid.
      """
      if len(segment) > 4:
          return False

      if not re.fullmatch(r'[0-9a-fA-F]{1,4}', segment):
          return False

      return True


def check_valid_netmask(netmask):
      '''
      Verifica daca o netmask este valida:
      - are 4 campuri separate prin .
      - fiecare camp este un numar intre 0 si 255
      - nu contine litere sau caractere speciale
      - bitii de 1 sunt consecutivi (255.255.255.0 - masca, 250.255.255.0 - nu este masca)
      '''
      check_valid_ipv4_address(netmask)
      try:
            value = ip_to_int(netmask)
      except ValueError as e:
            print(f"[ERROR] {e}")
            return False

      if value == 0:
            print(f"[ERROR] Netmask cannot be all 0s: {netmask}")
            return False
      inverted = ~value & 0xFFFFFFFF

      if (inverted + 1) & inverted != 0:
            print(f"[ERROR] Mask {netmask} is not a valid netmask.")
            return False
      return True


def check_valid_wildcard(wildcard):
      try:
            check_valid_ipv4_address(wildcard)
            value = ip_to_int(wildcard)

      except InvalidIPv4Address as exc:
            print(f"[ERROR] {exc}")
            return False

      except ValueError as e:
            print(f"[ERROR] {e}")
            return False

      return (value & (value + 1)) == 0


def check_valid_ipv4_network(net_str, mask_str):
      net_int = ip_to_int(net_str)
      mask_int = ip_to_int(mask_str)

      if net_int & mask_int != net_int:
            return False

      return True


def is_valid_acl_name(acl_name, type="standard"):
      if acl_name.isdigit():
            num = int(acl_name)
            if type == "standard":
                  if (1 <= num < 100) or (1300 <= num < 2000):
                        return True
            elif type == "extended":
                  if (100 <= num < 200) or (2000 <= num < 2700):
                        return True
            return False

      if re.fullmatch(r"[A-Za-z0-9_]+", acl_name):
            return True
      return False


def is_valid_pool_name(name):
    return bool(re.fullmatch(r"[A-Za-z0-9_]+", name))


def is_valid_port_number(port):
      return port.isdigit() and 0 <= int(port) <= 65535


def ip_to_int(ip_str):
      parts = ip_str.split('.')
      if len(parts) != 4:
            raise ValueError(f"Invalid IPv4 format: {ip_str}")

      num = 0
      for part in parts:
            if not part.isdigit():
                  raise ValueError(f"Invalid octet: {part}")
            octet = int(part)
            if octet < 0 or octet > 255:
                  raise ValueError(f"Octet out of range: {part}")
            num = (num << 8) | octet
      return num


def ip_in_network(ip, net_ip, net_mask):
      ip_int = ip_to_int(ip)
      net_ip_int, net_mask_int, net_network_int = ip_and_mask(net_ip, net_mask)
      return (ip_int & net_mask_int) == net_network_int


def ip_and_mask(ip_string, mask_string):
      ip_int = ip_to_int(ip_string)
      mask_int = ip_to_int(mask_string)
      return ip_int, mask_int, ip_int & mask_int


def net_of(ip_str, mask_str):
    return ip_to_int(ip_str) & ip_to_int(mask_str)


def subnets_overlaps(n1, m1, n2, m2):
      n1i, m1i = net_of(n1, m1), ip_to_int(m1)
      n2i, m2i = net_of(n2, m2), ip_to_int(m2)
      return (n1i & m2i) == n2i or (n2i & m1i) == n1i