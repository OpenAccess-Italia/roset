import ipaddress
import re

from ...foundation.parser.grammar_parser import Parser
from ...model.bgp_session import BgpSession
from ...model.interface import Interface, VlanInterface

# Interface Regex
IFACE_ENTITY: re.Pattern = re.compile(
    r"^set interfaces (.+?) ((unit (\d+) family .+ address (.+?/\d{1,3}) ?(.+)?)|(unit \d+ vlan-id (\d+))|(.+))$",
    re.MULTILINE
)

# BGP Local AS Regex
LOCAL_AS: re.Pattern = re.compile(r"^set routing-options autonomous-system (\d+)$", re.MULTILINE)

# BGP Regex
BGP_ENTITY: re.Pattern = re.compile(
    r"^set protocols bgp group (.+?) ((local-address (.+?))|(neighbor (.+?)( .+)?)|(peer-as (\d+))|(.+))$",
    re.MULTILINE
)


class JunosParser(Parser):
    __slots__ = ['_bgp_groups', '_vlan_interfaces']

    def __init__(self) -> None:
        super().__init__()

        self._bgp_groups: dict[str, dict] = {}
        self._vlan_interfaces: dict[str, dict] = {}

    def _parse_interfaces(self, content: str) -> None:
        entities = IFACE_ENTITY.findall(content)

        for entity in entities:
            self._parse_interface_entity(entity)

    def _parse_interface_entity(self, entity: str) -> None:
        if_name = entity[0].strip()

        # Vlan Configuration
        if entity[7]:
            unit = int(entity[7].strip())
            standard_name = f"{if_name}.{unit}"
            self._vlan_interfaces[standard_name] = {'name': standard_name, 'phy': if_name, 'vlan': unit, 'addr': set()}
        else:
            if if_name not in self._configuration.interfaces:
                self._configuration.interfaces[if_name] = Interface(if_name)

        # IP Configuration
        if entity[3] and entity[4]:
            unit = int(entity[3].strip())
            address = ipaddress.ip_interface(entity[4].strip())

            if unit == 0:
                self._configuration.interfaces[if_name].add_address(address)
            else:
                standard_name = f"{if_name}.{unit}"
                self._vlan_interfaces[standard_name]['addr'].add(address)

    def _parse_bgp(self, content: str) -> None:
        local_as_entity = LOCAL_AS.findall(content)
        if local_as_entity:
            self._configuration.local_as = int(local_as_entity[0].strip())

        entities = BGP_ENTITY.findall(content)
        for entity in entities:
            self._parse_bgp_entity(entity)

    def _parse_bgp_entity(self, entity: tuple) -> None:
        group_name = entity[0].strip()
        if group_name not in self._bgp_groups:
            self._bgp_groups[group_name] = {}

        # Local Address
        if entity[3]:
            self._bgp_groups[group_name]['local_address'] = entity[3].strip()
        # Neighbour
        if entity[5]:
            if 'neighbors' not in self._bgp_groups[group_name]:
                self._bgp_groups[group_name]['neighbors'] = set()
            self._bgp_groups[group_name]['neighbors'].add(entity[5].strip())
        # Remote AS
        if entity[8]:
            self._bgp_groups[group_name]['remote_as'] = int(entity[8].strip())

    def _on_complete(self) -> None:
        for group_name, group in self._bgp_groups.items():
            if 'neighbors' not in group or 'remote_as' not in group:
                continue

            if group['remote_as'] not in self._configuration.sessions:
                self._configuration.sessions[group['remote_as']] = BgpSession(
                    self._configuration.local_as, group['remote_as']
                )

            for neighbor in group['neighbors']:
                self._configuration.sessions[group['remote_as']].add_peering(
                    group['local_address'] if 'local_address' in group else None, neighbor, group_name
                )

        self._bgp_groups.clear()

        for vlan_iface in self._vlan_interfaces.values():
            self._configuration.interfaces[vlan_iface['name']] = VlanInterface(
                vlan_iface['name'], self._configuration.interfaces[vlan_iface['phy']], vlan_iface['vlan']
            )

            for addr in vlan_iface['addr']:
                self._configuration.interfaces[vlan_iface['name']].add_address(addr)

        self._vlan_interfaces.clear()
