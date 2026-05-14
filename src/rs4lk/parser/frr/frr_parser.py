import re
import ipaddress


from ...foundation.parser.grammar_parser import Parser
from ...model.bgp_session import BgpSession
from ...model.interface import Interface, VlanInterface


BGP_SECTION: re.Pattern = re.compile(r"^router bgp (\d+)\n(.*?)^\!", re.MULTILINE | re.DOTALL)
NEIGHBOR_REMOTE_AS: re.Pattern = re.compile(r"^\s+neighbor (\S+) remote-as (\d+)$", re.MULTILINE)
NEIGHBOR_UPDATE_SOURCE: re.Pattern = re.compile(r"^\s+neighbor (\S+) update-source (\S+)$", re.MULTILINE)

IFACE_SECTION: re.Pattern = re.compile(r"^interface (\S+)\n(.*?)^!", re.MULTILINE | re.DOTALL)
IFACE_ADDRESS: re.Pattern = re.compile(r"^\s+ip(?:v6)? address (\S+)", re.MULTILINE)
VLAN_IFACE: re.Pattern = re.compile(r"^(.+)\.(\d+)$")


class FrrParser(Parser):
    __slots__ = ['_bgp_groups', '_vlan_interfaces']

    def __init__(self) -> None:
        super().__init__()
        self._bgp_groups: dict = {}
        self._vlan_interfaces: dict[str, dict] = {}

    def _parse_interfaces(self, content: str) -> None:
        for name, body in IFACE_SECTION.findall(content):
            addresses = [ipaddress.ip_interface(a) for a in IFACE_ADDRESS.findall(body)]

            vlan_match = VLAN_IFACE.match(name)
            if vlan_match:
                phy_name = vlan_match.group(1)
                vlan_id = int(vlan_match.group(2))
                if phy_name not in self._configuration.interfaces:
                    self._configuration.interfaces[phy_name] = Interface(phy_name)
                self._vlan_interfaces[name] = {
                    'name': name,
                    'phy': phy_name,
                    'vlan': vlan_id,
                    'addr': set(addresses)
                }
            else:
                iface = Interface(name)
                for addr in addresses:
                    iface.add_address(addr)
                self._configuration.interfaces[name] = iface

    def _parse_bgp(self, content: str) -> None:
        match = BGP_SECTION.search(content)
        if not match:
            return

        local_as = int(match.group(1))
        self._configuration.local_as = local_as

        bgp_body = match.group(2)

        for remote_ip, remote_as_str in NEIGHBOR_REMOTE_AS.findall(bgp_body):
            remote_as = int(remote_as_str)

            if remote_as not in self._bgp_groups:
                self._bgp_groups[remote_as] = {'neighbors': set(), 'update_sources': {}}

            self._bgp_groups[remote_as]['neighbors'].add(remote_ip)

        for neighbor_ip, update_source in NEIGHBOR_UPDATE_SOURCE.findall(bgp_body):
            for remote_as, group in self._bgp_groups.items():
                if neighbor_ip in group['neighbors']:
                    group['update_sources'][neighbor_ip] = update_source
                    break

    def _on_complete(self) -> None:
        for remote_as, group in self._bgp_groups.items():
            if remote_as not in self._configuration.sessions:
                self._configuration.sessions[remote_as] = BgpSession(
                    self._configuration.local_as, remote_as
                )

            for neighbor in group['neighbors']:
                local_address = None
                if neighbor in group['update_sources']:
                    update_source = group['update_sources'][neighbor]
                    local_address = self._resolve_update_source(update_source, neighbor)

                self._configuration.sessions[remote_as].add_peering(local_address, neighbor)

        self._bgp_groups.clear()

        for vlan_iface in self._vlan_interfaces.values():
            self._configuration.interfaces[vlan_iface['name']] = VlanInterface(
                vlan_iface['name'], self._configuration.interfaces[vlan_iface['phy']], vlan_iface['vlan']
            )

            for addr in vlan_iface['addr']:
                self._configuration.interfaces[vlan_iface['name']].add_address(addr)

        self._vlan_interfaces.clear()

    def _resolve_update_source(self, update_source: str, neighbor_ip: str) -> str | None:
        try:
            return ipaddress.ip_address(update_source)
        except ValueError:
            pass

        if update_source in self._configuration.interfaces:
            iface = self._configuration.interfaces[update_source]
            neighbor_v = ipaddress.ip_address(neighbor_ip).version
            for addr in iface.addresses:
                if addr.version == neighbor_v:
                    return addr.ip

        return None

