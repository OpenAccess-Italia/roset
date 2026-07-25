import ipaddress

from .interface import Interface


class BgpSession:
    __slots__ = ['local_as', 'remote_as', 'peerings', 'relationship', 'iface', 'iface_idx', 'vlan']

    def __init__(self, local_as: int, remote_as: int) -> None:
        self.local_as: int = local_as
        self.remote_as: int = remote_as
        self.peerings: list[BgpPeering] = []

        self.relationship: int = 2

        self.iface: Interface | None = None
        self.iface_idx: int = -1
        self.vlan: int | None = None

    def add_peering(self, local_ip: str | None, remote_ip: str, group: str | None = None) -> None:
        self.peerings.append(BgpPeering(self, local_ip, remote_ip, group))

    def is_provider(self) -> bool:
        return self.relationship == 1

    def is_peer(self) -> bool:
        return self.relationship == 0

    def is_customer(self) -> bool:
        return self.relationship == 2

    def __repr__(self) -> str:
        return f"({self.local_as}=>{self.remote_as} (relationship={self.relationship}) " + \
            f"on iface=" + (self.iface.name if self.iface else "None") + f" (idx={self.iface_idx}" + \
            (f".{self.vlan}" if self.vlan else "") + f") with peerings={self.peerings})"


class BgpPeering:
    __slots__ = ['session', 'local_ip', 'remote_ip', 'group', 'iface_idx']

    def __init__(self, session: BgpSession, local_ip: str | None, remote_ip: str, group: str | None = None) -> None:
        self.session: BgpSession = session

        self.local_ip: (ipaddress.IPv4Address | ipaddress.IPv6Address |
                        ipaddress.IPv4Interface | ipaddress.IPv6Interface | None) = ipaddress.ip_address(local_ip) \
            if local_ip is not None else None
        self.remote_ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(remote_ip)
        self.group: str | None = group
        self.iface_idx: int = -1

    def __repr__(self) -> str:
        return f"{self.group}: local={self.local_ip} => remote={self.remote_ip}"
