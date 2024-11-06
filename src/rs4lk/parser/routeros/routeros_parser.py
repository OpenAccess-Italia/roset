import ipaddress
import re

from ...foundation.parser.grammar_parser import Parser
from ...model.bgp_session import BgpSession
from ...model.interface import Interface, VlanInterface

# Interface Regex
IFACE_SECTION: re.Pattern = re.compile(r"/?interface( .+)?\n((.+?\n)*?)/", re.MULTILINE)
VLAN_SECTION: re.Pattern = re.compile(r"^/interface vlan\n((.+?\n)*?)/", re.MULTILINE)
IPV4_SECTION: re.Pattern = re.compile(r"^/ip address\n((.+?\n)*?)/", re.MULTILINE)
IPV6_SECTION: re.Pattern = re.compile(r"^/ipv6 address\n((.+?\n)*?)/", re.MULTILINE)

# BGP Regex
BGP_SECTION: re.Pattern = re.compile(r"^/routing bgp connection\n((.+?\n)*?)/", re.MULTILINE)

# KV Regex
KV_ENTRY: re.Pattern = re.compile(r"^(set|add)( ?\[ (.+?) ] ?)?((.+?=.+?)*)$", re.MULTILINE)
KV_PAIR: re.Pattern = re.compile(r'(\S+)=("[^"]*"|\S+)')


class RouterosParser(Parser):
    __slots__ = ['_vlan_interfaces']

    def __init__(self) -> None:
        super().__init__()

        self._vlan_interfaces: dict[str, dict] = {}

    def _parse_interfaces(self, content: str) -> None:
        sections = IFACE_SECTION.findall(content)

        for section in sections:
            section_name = section[0].strip()
            if section_name == "ethernet":
                self._parse_interface_ethernet_section(section[1])
            elif section_name == "vlan":
                self._parse_interface_vlan_section(section[1])

        self._parse_ipv4_section(content)
        self._parse_ipv6_section(content)

    def _parse_interface_ethernet_section(self, section: str) -> None:
        if not section:
            return

        entries = KV_ENTRY.findall(self._clean_newlines(section))

        for entry in entries:
            filters = entry[2].strip()
            pairs = KV_PAIR.findall(filters)
            for key, value in pairs:
                if key == 'default-name':
                    self._configuration.interfaces[value.strip()] = Interface(value.strip())

    def _parse_interface_vlan_section(self, section: str) -> None:
        if not section:
            return

        entries = KV_ENTRY.findall(self._clean_newlines(section))

        for entry in entries:
            vlan_name = None
            vlan_id = None
            interface = None
            pairs = KV_PAIR.findall(entry[3].strip())
            for key, value in pairs:
                if key == 'interface':
                    interface = value.strip()
                elif key == 'name':
                    vlan_name = value.strip()
                elif key == 'vlan-id':
                    vlan_id = int(value.strip())

            self._vlan_interfaces[vlan_name] = {'name': vlan_name, 'phy': interface, 'vlan': vlan_id, 'addr': set()}

    def _parse_ipv4_section(self, content: str) -> None:
        section = IPV4_SECTION.findall(content)
        if not section:
            return

        entries = KV_ENTRY.findall(self._clean_newlines(section.pop()[0].strip()))

        for entry in entries:
            pairs = KV_PAIR.findall(entry[3].strip())
            self._ip_config(pairs)

    def _parse_ipv6_section(self, content: str) -> None:
        section = IPV6_SECTION.findall(content)
        if not section:
            return

        entries = KV_ENTRY.findall(self._clean_newlines(section.pop()[0].strip()))

        for entry in entries:
            pairs = KV_PAIR.findall(entry[3].strip())
            self._ip_config(pairs)

    def _parse_bgp(self, content: str) -> None:
        section = BGP_SECTION.findall(content)
        if not section:
            return

        entries = KV_ENTRY.findall(self._clean_newlines(section.pop()[0]))
        for entry in entries:
            pairs = KV_PAIR.findall(entry[3].strip())
            remote_as = None
            local_address = None
            remote_address = None

            for key, value in pairs:
                if key == "local.address":
                    local_address = value.strip()
                if key == "remote.address":
                    remote_address = value.strip()
                if key == "as":
                    self._configuration.local_as = int(value.strip())
                if key == ".as":
                    remote_as = int(value.strip())

            if remote_as and remote_address:
                if remote_as not in self._configuration.sessions:
                    self._configuration.sessions[remote_as] = BgpSession(self._configuration.local_as, remote_as)

                remote_address = re.sub(r'/\d+$', '', remote_address)
                self._configuration.sessions[remote_as].add_peering(local_address, remote_address)

    def _ip_config(self, pairs: list) -> None:
        interface = None
        address: str = ""
        for key, value in pairs:
            if key == "interface":
                interface = value
            if key == "address":
                address = value

        # Special rule, if the subnet is not specified, Routeros assumes /32 for IPv4 and /64 for IPv6
        if "/" in address:
            ip_address = ipaddress.ip_interface(address)
        else:
            temp_addr = ipaddress.ip_address(address)
            if temp_addr.version == 4:
                ip_address = ipaddress.ip_interface(f"{address}/32")
            else:
                ip_address = ipaddress.ip_interface(f"{address}/64")

        if interface in self._vlan_interfaces:
            self._vlan_interfaces[interface]['addr'].add(ip_address)
        else:
            if interface not in self._configuration.interfaces:
                self._configuration.interfaces[interface] = Interface(interface)

            self._configuration.interfaces[interface].add_address(ip_address)

    def _on_complete(self) -> None:
        for vlan_iface in self._vlan_interfaces.values():
            self._configuration.interfaces[vlan_iface['name']] = VlanInterface(
                vlan_iface['name'], self._configuration.interfaces[vlan_iface['phy']], vlan_iface['vlan']
            )

            for addr in vlan_iface['addr']:
                self._configuration.interfaces[vlan_iface['name']].add_address(addr)

        self._vlan_interfaces.clear()

    @staticmethod
    def _clean_newlines(text: str) -> str:
        return re.sub(' {2,}', '', text).replace('\\\n', '')
