import ipaddress
import logging
import random
from collections import OrderedDict
from typing import Any

from sortedcontainers import SortedDict
from sortedcontainers import SortedSet

from .. import utils
from ..foundation.configuration.vendor_configuration import VendorConfiguration
from ..foundation.exceptions import TopologyError
from ..model.collision_domain import CollisionDomain
from ..mrt.table_dump import TableDump
from ..webhooks.ripe_db import RipeDb

INTERNET_AS_NUM = 1


class Node:
    __slots__ = ['identifier', 'neighbours', '_iface_idx_to_cd']

    def __init__(self, identifier: Any) -> None:
        self.identifier: Any = identifier
        self.neighbours: SortedDict[int, dict[str, 'Neighbour']] = SortedDict()
        self._iface_idx_to_cd: SortedDict[int, str] = SortedDict()

    @property
    def name(self) -> str:
        return str(self.identifier)

    def connect_interface_to_cd(self, cd: str, iface_idx: int | None = None) -> int | None:
        new_idx = False
        if iface_idx is None:
            iface_idx = max(self.neighbours.keys()) + 1 if self.neighbours else 0
            new_idx = True

        if iface_idx in self.neighbours:
            return

        self.neighbours[iface_idx] = {}
        self._iface_idx_to_cd[iface_idx] = cd

        return iface_idx if new_idx else None

    def connect_to_neighbour(self, neighbour: 'Node', iface_idx: int | None = None) -> int | None:
        new_idx = False
        if iface_idx is None:
            iface_idx = max(self.neighbours.keys()) + 1 if self.neighbours else 0
            new_idx = True

        if new_idx:
            cd = CollisionDomain.get_instance().get(self.name, neighbour.name)
            self._iface_idx_to_cd[iface_idx] = cd
        else:
            cd = self._iface_idx_to_cd[iface_idx]

        if iface_idx not in self.neighbours:
            self.neighbours[iface_idx] = {}

        self.neighbours[iface_idx][neighbour.name] = Neighbour(self, iface_idx, cd, neighbour)

        return iface_idx if new_idx else None

    def connect_to_neighbour_by_cd(self, neighbour: 'Node', cd: str, iface_idx: int | None = None) -> int | None:
        new_idx = self.connect_interface_to_cd(cd, iface_idx)

        neighbour_iface_idx = iface_idx if new_idx is None else new_idx
        self.connect_to_neighbour(neighbour, neighbour_iface_idx)

        return new_idx if new_idx else None

    def add_local_iface_ip(self, iface_idx: int,
                           neighbour: 'Node',
                           addr: ipaddress.IPv4Interface | ipaddress.IPv6Interface,
                           vlan: int | None = None,
                           is_public: bool = False) -> None:
        if iface_idx not in self.neighbours:
            raise TopologyError(f"Interface idx={iface_idx} not found on `{self.name}`")

        if neighbour.name not in self.neighbours[iface_idx]:
            raise TopologyError(f"Neigbour {neighbour.name} not found on `{self.name}`")

        self.neighbours[iface_idx][neighbour.name].add_local_ip(addr, vlan, is_public)

    def get_node_by_name(self, name: str) -> ('Node', int):
        for iface_idx, neighbours in self.neighbours.items():
            if name in neighbours:
                return neighbours[name].neighbour, iface_idx

        return None, -1

    def get_neighbour_by_name(self, name: str) -> ('Neighbour', int):
        for iface_idx, neighbours in self.neighbours.items():
            if name in neighbours:
                return neighbours[name], iface_idx

        return None, -1

    def get_cd_by_iface_idx(self, iface_idx: int) -> str:
        if iface_idx not in self._iface_idx_to_cd:
            raise TopologyError(f"Interface with idx={iface_idx} not found on `{self.name}`")

        return self._iface_idx_to_cd[iface_idx]

    def __repr__(self) -> str:
        return f"Node {self.name} - neighbours={self.neighbours}"


class Client(Node):
    def __init__(self, local_as: int) -> None:
        super().__init__(local_as)

    @property
    def name(self) -> str:
        return f"as{self.identifier}_client"

    def __repr__(self) -> str:
        return f"Client {self.name} - neighbours={self.neighbours}"


class BgpRouter(Node):
    __slots__ = ['relationship', 'candidate', 'local_networks', 'announced_networks', 'remote_neighbours']

    def __init__(self, local_as: int, relationship: int | None) -> None:
        super().__init__(local_as)

        self.relationship: int | None = relationship
        self.candidate: bool = False
        self.local_networks: dict[int, list] = {4: [], 6: []}
        self.announced_networks: dict[int, list] = {4: [], 6: []}
        self.remote_neighbours: dict = {}

    @property
    def name(self) -> str:
        return f"as{self.identifier}"

    def is_provider(self) -> bool:
        return self.relationship == 1

    def is_peer(self) -> bool:
        return self.relationship == 0

    def is_customer(self) -> bool:
        return self.relationship == 2

    def is_candidate(self) -> bool:
        return self.candidate

    def add_local_network(self, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
        self.local_networks[net.version].append(net)

    def add_announced_network(self, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
        self.announced_networks[net.version].append(net)

    def connect_to_remote_neighbour(self, identifier: int,
                                    remote_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        if identifier not in self.remote_neighbours:
            self.remote_neighbours[identifier] = {4: [], 6: []}

        self.remote_neighbours[identifier][remote_ip.version].append(remote_ip)

    def __repr__(self) -> str:
        return f"{self.name} (relationship={self.relationship}) - " \
               f"neighbours={self.neighbours} - local_networks={self.local_networks} - " \
               f"remote_neighbours={self.remote_neighbours} - announced_networks={self.announced_networks})"


class Neighbour:
    __slots__ = ['src', 'idx', 'cd', 'neighbour', 'local_ips']

    def __init__(self, src: Node, idx: int, cd: str, neighbour: Node | None = None) -> None:
        self.src: Node = src
        self.idx: int = idx
        self.cd: str = cd
        self.neighbour: Node = neighbour

        self.local_ips: dict[int, list] = {4: [], 6: []}

    def add_local_ip(self, addr: ipaddress.IPv4Interface | ipaddress.IPv6Interface, vlan: int | None = None,
                     is_public: bool = False) -> None:
        self.local_ips[addr.version].append((vlan, addr, is_public))

    def get_local_ips(self, is_public: bool | None = None) -> dict[int, list]:
        if is_public is None:
            return self.local_ips

        return {4: [x for x in self.local_ips[4] if x[2] == is_public],
                6: [x for x in self.local_ips[6] if x[2] == is_public]}

    def get_neighbours_ips(self, is_public: bool | None = None) -> dict[int, list]:
        if not self.neighbour:
            return {4: [], 6: []}

        for neighbours in self.neighbour.neighbours.values():
            for neighbour_iface in neighbours.values():
                if neighbour_iface.cd == self.cd and self.src.identifier == neighbour_iface.neighbour.identifier:
                    return neighbour_iface.get_local_ips(is_public)

        return {4: [], 6: []}

    def __repr__(self) -> str:
        return f"{self.cd}|" + (f"{self.neighbour.name}" if self.neighbour else "N/D") + f" - ips={self.local_ips})"


class Topology:
    __slots__ = ['_vendor_config', '_nodes', '_table_dump']

    def __init__(self, vendor_config: VendorConfiguration, table_dump: TableDump) -> None:
        self._vendor_config: VendorConfiguration = vendor_config
        self._nodes: OrderedDict = OrderedDict()
        self._table_dump: TableDump = table_dump

        self._build()

    def _build(self) -> None:
        logging.info("Creating topology...")

        self._infer_bgp_relationships()

        # First, add the candidate router
        candidate_local_as = self._vendor_config.local_as
        candidate_router = BgpRouter(candidate_local_as, None)
        candidate_router.candidate = True
        # Layout all the declared interfaces inside the device
        for iface_idx in SortedSet(self._vendor_config.iface_to_iface_idx.values()):
            cd = CollisionDomain.get_instance().get(
                str(candidate_local_as),
                f"as{candidate_local_as}_{iface_idx}"
            )
            candidate_router.connect_interface_to_cd(cd, iface_idx)
        self._nodes[candidate_local_as] = candidate_router

        # First, directly connected ones
        for as_num, session in self._vendor_config.sessions.items():
            if session.iface:
                neighbour_router = BgpRouter(as_num, session.relationship)
                self._nodes[as_num] = neighbour_router

                cd = candidate_router.get_cd_by_iface_idx(session.iface_idx)
                candidate_router.connect_to_neighbour(neighbour_router, session.iface_idx)
                neighbour_router.connect_to_neighbour_by_cd(candidate_router, cd)

                for peering in session.peerings:
                    if peering.local_ip is None:
                        raise TopologyError(f"Direct peering with AS{as_num} does not declare a local IP")
                    if type(peering.local_ip) not in [ipaddress.IPv4Interface, ipaddress.IPv6Interface]:
                        raise TopologyError(f"Direct peering with AS{as_num} does not declare a local IP interface")

                    r_iface_ip = ipaddress.ip_interface(f"{peering.remote_ip}/{peering.local_ip.network.prefixlen}")
                    neighbour_router.add_local_iface_ip(
                        0, candidate_router, r_iface_ip, vlan=session.vlan, is_public=True
                    )
                    candidate_router.add_local_iface_ip(
                        session.iface_idx, neighbour_router, peering.local_ip, vlan=session.vlan, is_public=True
                    )

        # Fill in missing candidate interfaces
        for i in range(0, max(candidate_router.neighbours.keys()) + 1):
            if i in candidate_router.neighbours:
                continue

            cd = CollisionDomain.get_instance().get(str(candidate_local_as), f"dummy_net_{i}")
            candidate_router.connect_interface_to_cd(cd, i)

        # Get all DC providers
        providers_routers = list(filter(lambda x: x.is_provider(), self._nodes.values()))
        providers_ases = set(map(lambda x: x.identifier, providers_routers))

        # All peering LANs between multihops and providers are in a private LAN
        peering_networks_v4 = ipaddress.ip_network("10.0.0.0/8").subnets(new_prefix=24)
        peering_networks_v6 = ipaddress.ip_network("fc00::/7").subnets(new_prefix=120)

        # Get sessions without interface (multihop peerings)
        for as_num, session in self._vendor_config.sessions.items():
            if not session.iface:
                # Put them as customers (2) of the providers
                neighbour_router = BgpRouter(as_num, 2)
                self._nodes[as_num] = neighbour_router

                for provider_router in self._get_connected_providers_by_as_num(providers_ases, as_num):
                    neighbour_iface_idx = neighbour_router.connect_to_neighbour(provider_router)
                    provider_iface_idx = provider_router.connect_to_neighbour(neighbour_router)

                    # Assign new peering subnet to provider
                    peering_network_v4 = next(peering_networks_v4)
                    peering_ips_v4 = peering_network_v4.hosts()
                    peering_prefixlen_v4 = peering_network_v4.prefixlen

                    peering_network_v6 = next(peering_networks_v6)
                    peering_ips_v6 = peering_network_v6.hosts()
                    peering_prefixlen_v6 = peering_network_v6.prefixlen

                    for peering in session.peerings:
                        multihop_subnet = 32 if peering.remote_ip.version == 4 else 128
                        # Assign the IP that the candidate expects for the peering
                        r_iface_ip = ipaddress.ip_interface(f"{peering.remote_ip}/{multihop_subnet}")
                        neighbour_router.add_local_iface_ip(
                            neighbour_iface_idx, provider_router, r_iface_ip, is_public=False
                        )

                        # Assign peering IPs
                        ip_n = next(peering_ips_v4) if peering.remote_ip.version == 4 else next(peering_ips_v6)
                        ip_p = next(peering_ips_v4) if peering.remote_ip.version == 4 else next(peering_ips_v6)
                        prefix = peering_prefixlen_v4 if peering.remote_ip.version == 4 else peering_prefixlen_v6
                        neighbour_router.add_local_iface_ip(
                            neighbour_iface_idx,
                            provider_router,
                            ipaddress.ip_interface(f"{ip_n}/{prefix}"),
                            is_public=True
                        )
                        provider_router.add_local_iface_ip(
                            provider_iface_idx,
                            neighbour_router,
                            ipaddress.ip_interface(f"{ip_p}/{prefix}"),
                            is_public=True
                        )

                        # Announce the network to reach (to the provider)
                        # We do not know the subnet, put a /24 (v4) or /48 (v6)
                        subnet = 24 if peering.remote_ip.version == 4 else 48
                        fake_iface = ipaddress.ip_interface(f"{r_iface_ip.network.network_address}/{subnet}")
                        neighbour_router.add_announced_network(fake_iface.network)

                # Remember the multihop connection with the candidate router
                for peering in session.peerings:
                    neighbour_router.connect_to_remote_neighbour(candidate_router.identifier, peering.local_ip)

        # Create a fake AS that represents the "Internet" with a client (for the spoofing checks)
        internet_router = BgpRouter(INTERNET_AS_NUM, -1)
        self._nodes[INTERNET_AS_NUM] = internet_router
        internet_router.add_announced_network(ipaddress.IPv4Network("0.0.0.0/0"))
        internet_router.add_announced_network(ipaddress.IPv6Network("0::0/0"))

        internet_router_client = Client(1)
        internet_router.connect_to_neighbour(internet_router_client)
        internet_router_client.connect_to_neighbour(internet_router)

        # Final additions to the provider
        for provider_router in providers_routers:
            peering_network_v4 = next(peering_networks_v4)
            peering_ips_v4 = peering_network_v4.hosts()
            peering_prefixlen_v4 = peering_network_v4.prefixlen

            peering_network_v6 = next(peering_networks_v6)
            peering_ips_v6 = peering_network_v6.hosts()
            peering_prefixlen_v6 = peering_network_v6.prefixlen

            # Add originated networks
            provider_originated_networks = self._get_originated_networks_by_as_num(provider_router.identifier)
            for net in provider_originated_networks:
                provider_router.add_local_network(net)
                provider_router.add_announced_network(net)
            utils.aggregate_v4_6_networks(provider_router.local_networks)

            # Connect each provider to the "Internet"
            internet_iface_idx = internet_router.connect_to_neighbour(provider_router)
            internet_router.add_local_iface_ip(
                internet_iface_idx,
                provider_router,
                ipaddress.ip_interface(f"{next(peering_ips_v4)}/{peering_prefixlen_v4}"),
                is_public=True
            )
            internet_router.add_local_iface_ip(
                internet_iface_idx,
                provider_router,
                ipaddress.ip_interface(f"{next(peering_ips_v6)}/{peering_prefixlen_v6}"),
                is_public=True
            )
            provider_iface_idx = provider_router.connect_to_neighbour(internet_router)
            provider_router.add_local_iface_ip(
                provider_iface_idx,
                internet_router,
                ipaddress.ip_interface(f"{next(peering_ips_v4)}/{peering_prefixlen_v4}"),
                is_public=True
            )
            provider_router.add_local_iface_ip(
                provider_iface_idx,
                internet_router,
                ipaddress.ip_interface(f"{next(peering_ips_v6)}/{peering_prefixlen_v6}"),
                is_public=True
            )

            # Add provider client
            neighbour_client = Client(provider_router.identifier)
            neighbour_client.connect_to_neighbour(provider_router)
            provider_router.connect_to_neighbour(neighbour_client)

        # Finally, add a client to the candidate AS (with an unused interface)
        candidate_router_client = Client(candidate_local_as)
        empty_iface_idx = -1
        for iface_idx in reversed(candidate_router.neighbours):
            if not candidate_router.neighbours[iface_idx]:
                empty_iface_idx = iface_idx
                break

        if empty_iface_idx == -1:
            raise TopologyError(f"No empty interface available to connect `{candidate_router.name}`")

        cd = candidate_router.get_cd_by_iface_idx(empty_iface_idx)
        candidate_router.connect_to_neighbour(candidate_router_client, empty_iface_idx)
        candidate_router_client.connect_to_neighbour_by_cd(candidate_router, cd)

    def _infer_bgp_relationships(self) -> None:
        logging.info("Inferring BGP relationships...")

        (import_rules, _) = RipeDb.get_instance().get_local_as_rules(self._vendor_config.local_as)

        # Remove 'afi XXYY' if it is a mp-import
        import_rules = set([" ".join(x.split(' ')[2:]) if 'afi' in x else x for x in import_rules])

        for remote_as_num, session in self._vendor_config.sessions.items():
            found = False
            rule_pattern = f"from AS{remote_as_num}"
            for rule in import_rules:
                # Assign relationships a-la CAIDA (1=provider, 0=peer, 2=customer)
                if rule_pattern in rule:
                    found = True

                    if 'any' in rule.lower():
                        session.relationship = 1
                    else:
                        session.relationship = 2

                    logging.info(f"Found relationship {rule_pattern}: {session.relationship}.")

                    break

            if not found:
                logging.warning(f"Cannot find relationship {rule_pattern}, putting it as peer (0).")
                session.relationship = 0

        logging.debug(f"Resulting sessions: {self._vendor_config.sessions}")

    def _get_connected_providers_by_as_num(self, providers_ases: set[int], as_num: int) -> list[Node]:
        as_providers = self._get_providers_of_as(as_num)
        connected_providers = as_providers.intersection(providers_ases)
        if len(connected_providers) == 0:
            logging.warning(f"No providers found for AS{as_num}, choosing a random one.")
            connected_providers = {random.choice(list(providers_ases))}

        return [self._nodes[x] for x in connected_providers]

    def _get_providers_of_as(self, as_num: int) -> set[int]:
        providers = set()
        rib_entries = self._table_dump.get_by_as_origin(as_num)
        for entry in rib_entries:
            providers.update(set(entry.as_path[:-1]))

        return providers

    def _get_originated_networks_by_as_num(self, as_num: int) -> set:
        rib_entries = self._table_dump.get_by_as_origin(as_num)
        return set(map(lambda x: x.network, rib_entries))

    def all(self) -> Any:
        return self._nodes.items()

    def get(self, identifier: int) -> Node:
        if identifier not in self._nodes:
            raise TopologyError(f"Node {identifier} not found in topology")

        return self._nodes[identifier]
