import ipaddress


class NeighborInfo:
    __slots__ = ['neighbor_as', 'neighbor_type', 'peerings', 'announced_networks']

    def __init__(self, neighbor_as: int, neighbor_type: int) -> None:
        self.neighbor_as: int = neighbor_as
        self.neighbor_type: int = neighbor_type
        # machine_name -> {4: [ip1, ip2, ...], 6: [ip1, ...]}
        self.peerings: dict[str, dict[int, list]] = {}
        # machine_name -> {4: set(networks), 6: set(networks)}
        self.announced_networks: dict[str, dict[int, set]] = {}

    def add_peering(self, border_router_machine_name: str) -> None:
        if border_router_machine_name not in self.peerings:
            self.peerings[border_router_machine_name] = {4: [], 6: []}
            self.announced_networks[border_router_machine_name] = {4: set(), 6: set()}

    def add_peering_ip(self, border_router_machine_name: str, version: int,
                       ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> None:
        self.peerings[border_router_machine_name][version].append(ip)

    def add_announced_networks(self, border_router_machine_name: str, version: int, networks: set) -> None:
        self.announced_networks[border_router_machine_name][version].update(networks)

    def __repr__(self) -> str:
        return (f"NeighborInfo AS{self.neighbor_as} (type={self.neighbor_type}, "
                f"peerings={self.peerings}, "
                f"announced_networks={self.announced_networks})")