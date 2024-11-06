import ipaddress
import re

from ...foundation.parser.grammar_parser import Parser
from ...model.bgp_session import BgpSession
from ...model.interface import Interface, VlanInterface

# Interface Regex
IFACE_SECTION: re.Pattern = re.compile(
    r"^interface( preconfigure)? (.*?)(\s+.+)*?\n(( .+?\n)*?)!", re.MULTILINE
)
IFACE_IPV4_CONFIG: re.Pattern = re.compile(r"^\s+ipv4 address (.+) (.+)$", re.MULTILINE)
IFACE_IPV6_CONFIG: re.Pattern = re.compile(r"^\s+ipv6 address (.+)/(\d{1,3})$", re.MULTILINE)
IFACE_ENCAPSULATION_CONFIG: re.Pattern = re.compile(
    r"^\s+encapsulation dot1q (\d+)( second-dot1q (\d+))?$", re.MULTILINE
)
IFACE_SHUTDOWN_CONFIG: re.Pattern = re.compile(r"^\s+shutdown$", re.MULTILINE)

# BGP Regex
BGP_SECTION: re.Pattern = re.compile(r"^router bgp (.*?)\n(( +.+?\n)*?)!", re.MULTILINE)

# BGP Neighbour Regex
NEIGH_SECTION: re.Pattern = re.compile(r"^\s+neighbor (.*?)\n((\s+.+?\n)*?)\s+!", re.MULTILINE)
NEIGH_REMOTE_AS: re.Pattern = re.compile(r"^\s+remote-as (\d+)$", re.MULTILINE)
NEIGH_UPDATE_SOURCE: re.Pattern = re.compile(r"^\s+update-source (.+)$", re.MULTILINE)


class IosxrParser(Parser):
    __slots__ = ['_bgp_groups', '_vlan_interfaces']

    def __init__(self) -> None:
        super().__init__()

        self._bgp_groups = {}
        self._vlan_interfaces: dict[str, dict] = {}

    def _parse_interfaces(self, content: str) -> None:
        sections = IFACE_SECTION.findall(content)

        for section in sections:
            self._parse_interface_section(section)

    def _parse_interface_section(self, section: str) -> None:
        if_name = section[1].strip()
        if if_name == 'all':
            return

        active = True
        addresses = set()
        vlan_id = None

        if_statements = section[3]
        shutdown_conf = IFACE_SHUTDOWN_CONFIG.findall(if_statements)
        if shutdown_conf:
            active = False

        ipv4_conf = IFACE_IPV4_CONFIG.findall(if_statements)
        if ipv4_conf:
            for ipv4_addr in ipv4_conf:
                ipv4_address = ipv4_addr[0].strip()
                ipv4_mask = sum(bin(int(x)).count('1') for x in ipv4_addr[1].strip().split('.'))
                addresses.add(f"{ipv4_address}/{ipv4_mask}")

        ipv6_conf = IFACE_IPV6_CONFIG.findall(if_statements)
        if ipv6_conf:
            for ipv6_addr in ipv6_conf:
                ipv6_address = ipv6_addr[0].strip()
                ipv6_mask = ipv6_addr[1].strip()
                addresses.add(f"{ipv6_address}/{ipv6_mask}")

        encapsulation_conf = IFACE_ENCAPSULATION_CONFIG.findall(if_statements)
        if encapsulation_conf:
            vlan_id = int(encapsulation_conf[0][0].strip())

        if active:
            if if_name not in self._configuration.interfaces:
                if vlan_id is not None:
                    (phy, _) = if_name.split('.')
                    self._vlan_interfaces[if_name] = {'name': if_name, 'phy': phy, 'vlan': vlan_id, 'addr': set()}
                else:
                    self._configuration.interfaces[if_name] = Interface(if_name)
            for address in addresses:
                if vlan_id is not None:
                    self._vlan_interfaces[if_name]['addr'].add(address)
                else:
                    ip_address = ipaddress.ip_interface(address)
                    self._configuration.interfaces[if_name].add_address(ip_address)
        else:
            if if_name in self._vlan_interfaces:
                del self._vlan_interfaces[if_name]
            elif if_name in self._configuration.interfaces:
                del self._configuration.interfaces[if_name]

    def _parse_bgp(self, content: str) -> None:
        sections = BGP_SECTION.findall(content)
        if not sections:
            return
        sections = sections.pop()

        self._configuration.local_as = int(sections[0].strip())

        neighbors = NEIGH_SECTION.findall(sections[1])
        for neighbor in neighbors:
            remote_ip = neighbor[0].strip()

            remote_as = None
            remote_as_statement = NEIGH_REMOTE_AS.findall(neighbor[1])
            if remote_as_statement:
                remote_as = int(remote_as_statement[0].strip())

            local_iface = None
            update_source_statement = NEIGH_UPDATE_SOURCE.findall(neighbor[1])
            if update_source_statement:
                local_iface = update_source_statement[0].strip()

            if remote_ip and remote_as:
                if remote_as not in self._bgp_groups:
                    self._bgp_groups[remote_as] = {}

                self._bgp_groups[remote_as]['local_iface'] = local_iface

                if 'neighbors' not in self._bgp_groups[remote_as]:
                    self._bgp_groups[remote_as]['neighbors'] = set()
                self._bgp_groups[remote_as]['neighbors'].add(remote_ip)

                self._bgp_groups[remote_as]['remote_as'] = remote_as

    def _on_complete(self) -> None:
        for group in self._bgp_groups.values():
            if group['remote_as'] not in self._configuration.sessions:
                self._configuration.sessions[group['remote_as']] = BgpSession(
                    self._configuration.local_as, group['remote_as']
                )

            local_iface = None
            if 'local_iface' in group:
                if group['local_iface'] in self._configuration.interfaces:
                    local_iface = self._configuration.interfaces[group['local_iface']]

                for neighbor in group['neighbors']:
                    local_address = None
                    if local_iface:
                        neighbor_v = ipaddress.ip_address(neighbor).version
                        v_addresses = [x.ip for x in local_iface.addresses if x.version == neighbor_v]
                        if len(v_addresses) > 0:
                            local_address = v_addresses.pop(0)

                    self._configuration.sessions[group['remote_as']].add_peering(local_address, neighbor)

        self._bgp_groups.clear()

        for vlan_iface in self._vlan_interfaces.values():
            self._configuration.interfaces[vlan_iface['name']] = VlanInterface(
                vlan_iface['name'], self._configuration.interfaces[vlan_iface['phy']], vlan_iface['vlan']
            )

            for addr in vlan_iface['addr']:
                ip_address = ipaddress.ip_interface(addr)
                self._configuration.interfaces[vlan_iface['name']].add_address(ip_address)

        self._vlan_interfaces.clear()
