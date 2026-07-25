from __future__ import annotations

import ipaddress
import logging
import random
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from sortedcontainers import SortedDict
from sortedcontainers import SortedSet

from .. import utils
from ..foundation.exceptions import TopologyError
from ..model.collision_domain import CollisionDomain
from ..mrt.table_dump import TableDump
from ..webhooks.ripe_db import RipeDb

if TYPE_CHECKING:
    from ..foundation.configuration.vendor_configuration import VendorConfiguration
    from .as_candidate import AsCandidate
    from .bgp_session import BgpSession

INTERNET_AS_NUM = 1111


class Node:
    __slots__ = ['identifier', 'neighbours', '_iface_idx_to_cd', 'static_routes']

    def __init__(self, identifier: Any) -> None:
        self.identifier: Any = identifier
        self.neighbours: SortedDict[int, dict[str, 'Neighbour']] = SortedDict()
        self._iface_idx_to_cd: SortedDict[int, str] = SortedDict()
        self.static_routes: list[str] = []

    @property
    def name(self) -> str:
        return str(self.identifier)

    @property
    def machine_name(self) -> str:
        return self.name

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

    def connect_to_neighbour(self, neighbour: 'Node', iface_idx: int | None = None, cd: str | None = None) -> int | None:
        new_idx = iface_idx is None
        if new_idx:
            iface_idx = max(self.neighbours.keys()) + 1 if self.neighbours else 0

        if iface_idx not in self._iface_idx_to_cd:
            if cd is None:
                cd = CollisionDomain.get_instance().get(self.machine_name, neighbour.machine_name)
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
    def __init__(self, local_as: int, router_machine_name: str | None = None) -> None:
        super().__init__(local_as)
        self._router_machine_name = router_machine_name

    @property
    def name(self) -> str:
        if self._router_machine_name:
            return f"{self._router_machine_name}_client"
        return f"as{self.identifier}_client"

    @property
    def machine_name(self) -> str:
        return self.name


class BgpRouter(Node):
    __slots__ = ['relationship', 'candidate', 'local_networks', 'announced_networks', 'remote_neighbours', '_machine_name']

    def __init__(self, local_as: int, relationship: int | None) -> None:
        super().__init__(local_as)

        self.relationship: int | None = relationship
        self.candidate: bool = False
        self.local_networks: dict[int, list] = {4: [], 6: []}
        self.announced_networks: dict[int, list] = {4: [], 6: []}
        self.remote_neighbours: dict = {}
        self._machine_name: str | None = None

    @property
    def name(self) -> str:
        return f"as{self.identifier}"

    @property
    def machine_name(self) -> str:
        return self._machine_name if self._machine_name else self.name

    def set_machine_name(self, name: str) -> None:
        self._machine_name = name

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
    __slots__ = ['_vendor_config', '_as_candidate', '_nodes', '_table_dump']

    def __init__(self, vendor_config: 'VendorConfiguration | None' = None, table_dump: TableDump | None = None,
                 as_candidate: 'AsCandidate | None' = None) -> None:
        if not as_candidate and (vendor_config is None or table_dump is None):
            raise TopologyError("vendor_config and table_dump are required when not using as_candidate")

        self._vendor_config: 'VendorConfiguration' = vendor_config
        self._as_candidate: 'AsCandidate | None' = as_candidate
        self._nodes: OrderedDict = OrderedDict()
        self._table_dump: TableDump = table_dump

        self._build()

    def _build(self) -> None:
        logging.info("Creating topology...")

        if self._as_candidate:
            self._build_multi_router_topology()
        else:
            self._infer_bgp_relationships()
            self._build_single_router_topology()

    def _build_single_router_topology(self) -> None:
        logging.info("Building single-router topology...")

        # First, add the candidate router
        candidate_local_as = self._vendor_config.local_as
        candidate_router = BgpRouter(candidate_local_as, None)
        candidate_router.candidate = True
        candidate_router.set_machine_name(f"as{candidate_local_as}")
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

        internet_router_client = Client(INTERNET_AS_NUM)
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

    def _build_multi_router_topology(self) -> None:
        candidate_routers = {}
        for rc in self._as_candidate.routers:
            rc.candidate = True  # rc is already a RouterCandidate with name = machine_name.
            
            vendor_config = rc.vendor_config
            if vendor_config and vendor_config.interfaces:
                for iface_idx in SortedSet(vendor_config.iface_to_iface_idx.values()):
                    cd = CollisionDomain.get_instance().get(
                        rc.machine_name,
                        f"{rc.machine_name}_{iface_idx}"
                    )
                    rc.connect_interface_to_cd(cd, iface_idx)

            candidate_routers[rc.router_name] = rc
            self._nodes[rc.machine_name] = rc

        self._infer_bgp_relationships_multi_router(candidate_routers)

        external_sessions = self._collect_external_sessions(candidate_routers)
        self._add_external_neighbors(candidate_routers, external_sessions)

        self._connect_candidate_routers_internal(candidate_routers)

        self._add_dummy_interfaces_candidate_routers(candidate_routers)

        self._add_internet_and_providers(candidate_routers)

    def _infer_bgp_relationships_multi_router(self, candidate_routers: dict) -> None:
        logging.info("Inferring BGP relationships for multi-router AS...")

        for router_name, router in candidate_routers.items():
            vendor_config = None
            for rc in self._as_candidate.routers:
                if rc.router_name == router_name:
                    vendor_config = rc.vendor_config
                    break

            if not vendor_config:
                continue

            (import_rules, _) = RipeDb.get_instance().get_local_as_rules(router.identifier)

            import_rules = set([" ".join(x.split(' ')[2:]) if 'afi' in x else x for x in import_rules])

            for remote_as_num, session in vendor_config.sessions.items():
                if remote_as_num == router.identifier:
                    session.relationship = -1
                    continue

                found = False

                local_rel = RipeDb.get_instance().get_local_relationship(router.identifier, remote_as_num)
                if local_rel is not None:
                    session.relationship = local_rel
                    rel_name = {0: "peer", 1: "provider", 2: "customer"}.get(local_rel, "unknown")
                    logging.info(f"Found LOCAL relationship AS{router.identifier} -> AS{remote_as_num}: {rel_name} ({local_rel}).")
                    found = True

                if not found:
                    rule_pattern = f"from AS{remote_as_num}"
                    for rule in import_rules:
                        if rule_pattern in rule:
                            found = True
                            if 'any' in rule.lower():
                                session.relationship = 1
                            else:
                                session.relationship = 2
                            break

                if not found:
                    session.relationship = 0

                if session.relationship is not None:
                    router.relationship = session.relationship

    def _collect_external_sessions(self, candidate_routers: dict) -> list[tuple[str, str, BgpSession]]:
        external_sessions = []

        for router_name, router in candidate_routers.items():
            vendor_config = None
            for rc in self._as_candidate.routers:
                if rc.router_name == router_name:
                    vendor_config = rc.vendor_config
                    break

            if not vendor_config:
                continue

            for remote_as, session in vendor_config.sessions.items():
                if remote_as == self._as_candidate.local_as:
                    continue

                external_sessions.append((router_name, remote_as, session))

        return external_sessions

    def _add_external_neighbors(self, candidate_routers: dict, external_sessions: list[tuple[str, str, BgpSession]]) -> None:
        processed_external_as: dict[int, BgpRouter] = {}
        processed_connections: set[tuple[str, int, int]] = set()

        for router_name, as_num, session in external_sessions:
            if not session.iface:
                continue

            for peering in session.peerings:
                if peering.local_ip is None:
                    continue

                connection_key = (router_name, as_num, peering.iface_idx)
                if connection_key in processed_connections:
                    continue
                processed_connections.add(connection_key)

                if as_num not in processed_external_as:
                    neighbour_router = BgpRouter(as_num, session.relationship)
                    self._nodes[as_num] = neighbour_router
                    processed_external_as[as_num] = neighbour_router
                else:
                    neighbour_router = processed_external_as[as_num]
                    if session.relationship is not None and neighbour_router.relationship is None:
                        neighbour_router.relationship = session.relationship

                router = candidate_routers[router_name]

                cd = router.get_cd_by_iface_idx(peering.iface_idx)
                router.connect_to_neighbour(neighbour_router, peering.iface_idx)
                # Always create a new interface on the remote AS for this collision domain.
                neighbour_iface_idx = neighbour_router.connect_interface_to_cd(cd)
                if neighbour_iface_idx is None:
                    # The collision domain already exists; find the existing iface_idx.
                    for iface_idx, iface_cd in neighbour_router._iface_idx_to_cd.items():
                        if iface_cd == cd:
                            neighbour_iface_idx = iface_idx
                            break
                neighbour_router.connect_to_neighbour(router, neighbour_iface_idx, cd=cd)

                r_iface_ip = ipaddress.ip_interface(f"{peering.remote_ip}/{peering.local_ip.network.prefixlen}")
                neighbour_router.add_local_iface_ip(
                    neighbour_iface_idx, router, r_iface_ip, vlan=session.vlan, is_public=True
                )
                router.add_local_iface_ip(
                    peering.iface_idx, neighbour_router, peering.local_ip, vlan=session.vlan, is_public=True
                )

    def _connect_candidate_routers_internal(self, candidate_routers: dict) -> None:
        logging.info("Connecting candidate routers internally (iBGP)...")

        connected_pairs: set[tuple[str, str]] = set()

        for router_name, router in candidate_routers.items():
            vendor_config = None
            for rc in self._as_candidate.routers:
                if rc.router_name == router_name:
                    vendor_config = rc.vendor_config
                    break

            if not vendor_config:
                continue

            for remote_as, session in vendor_config.sessions.items():
                if remote_as != self._as_candidate.local_as:
                    continue

                for peering in session.peerings:
                    if peering.local_ip is None or peering.remote_ip is None:
                        continue

                    logging.debug(f"  Checking {router_name}: local={peering.local_ip} -> remote={peering.remote_ip}")

                    continue_external = False
                    for other_name, other_router in candidate_routers.items():
                        if other_name == router_name:
                            continue

                        pair_key = tuple(sorted([router_name, other_name]))
                        if pair_key in connected_pairs:
                            continue

                        if peering.iface_idx in router.neighbours:
                            for existing_neighbour_name, existing_neighbour in router.neighbours[peering.iface_idx].items():
                                if existing_neighbour.neighbour.machine_name == other_router.machine_name:
                                    logging.debug(f"    Skipping {router_name} -> {other_name}: already on iface {peering.iface_idx}")
                                    continue_external = True
                                    break
                            if continue_external:
                                continue

                        other_vendor_config = None
                        other_session_match = None
                        other_peering_match = None
                        for rc in self._as_candidate.routers:
                            if rc.router_name == other_name:
                                other_vendor_config = rc.vendor_config
                                break

                        if not other_vendor_config:
                            continue

                        for other_remote_as, other_sess in other_vendor_config.sessions.items():
                            if other_remote_as != self._as_candidate.local_as:
                                continue

                            for other_peering in other_sess.peerings:
                                logging.debug(f"    vs {other_name}: local={other_peering.local_ip} -> remote={other_peering.remote_ip}")
                                if other_peering.remote_ip == peering.local_ip.ip:
                                    other_session_match = other_sess
                                    other_peering_match = other_peering
                                    break
                            if other_session_match:
                                break

                        if other_session_match is None:
                            continue

                        if peering.iface_idx in router.neighbours:
                            for existing_neighbour_name, existing_neighbour in router.neighbours[peering.iface_idx].items():
                                if existing_neighbour.neighbour.machine_name == other_router.machine_name:
                                    logging.debug(f"  Skipping {router_name} -> {other_name}: already connected on iface {peering.iface_idx}")
                                    continue_external = True
                                    break
                            if continue_external:
                                continue

                        if peering.iface_idx in router.neighbours:
                            for existing_neighbour_name, existing_neighbour in router.neighbours[peering.iface_idx].items():
                                if existing_neighbour.neighbour.machine_name == other_router.machine_name:
                                    logging.debug(f"    Skipping: already connected")
                                    continue_external = True
                                    break
                            if continue_external:
                                continue

                        connected_pairs.add(pair_key)

                        cd = router.get_cd_by_iface_idx(peering.iface_idx)

                        router.connect_to_neighbour(other_router, peering.iface_idx, cd)
                        other_router._iface_idx_to_cd[other_peering_match.iface_idx] = cd
                        other_router.connect_to_neighbour(router, other_peering_match.iface_idx, cd)

                        router.add_local_iface_ip(
                            peering.iface_idx, other_router, peering.local_ip,
                            vlan=session.vlan, is_public=True
                        )
                        other_router.add_local_iface_ip(
                            other_peering_match.iface_idx, router, other_peering.local_ip,
                            vlan=other_sess.vlan, is_public=True
                        )

                        logging.info(f"  Connected {router_name} (iface {peering.iface_idx}) <-> {other_name} (iface {other_peering_match.iface_idx}) via {cd} (iBGP)")

        # Handle non-directly-connected iBGP sessions (multihop iBGP)
        # These occur when iBGP peers are not on the same subnet and
        # LPM in _infer_bgp_dc_sessions couldn't find a matching interface.
        # We create a direct L2 link between the two routers.
        self._connect_non_dc_ibgp(candidate_routers, connected_pairs)

    def _connect_non_dc_ibgp(self, candidate_routers: dict,
                               connected_pairs: set[tuple[str, str]]) -> None:
        logging.info("Connecting non-directly-connected iBGP sessions...")

        router_iface_ips: dict[str, dict[str, int]] = {}
        for router_name, router in candidate_routers.items():
            ips: dict[str, int] = {}
            for rc in self._as_candidate.routers:
                if rc.router_name == router_name and rc.vendor_config:
                    for iface_name, iface in rc.vendor_config.interfaces.items():
                        iface_real = iface.phy.name if hasattr(iface, 'phy') else iface.name
                        if iface_real not in rc.vendor_config.iface_to_iface_idx:
                            continue
                        iface_idx = rc.vendor_config.iface_to_iface_idx[iface_real]
                        for addr in iface.addresses:
                            ips[str(addr.ip)] = iface_idx
                    break
            router_iface_ips[router_name] = ips

        # First pass: collect all non-DC iBGP pairs with their interface info
        pairs: list[tuple[str, int, str, int, str, str]] = []

        for router_name, router in candidate_routers.items():
            vendor_config = None
            for rc in self._as_candidate.routers:
                if rc.router_name == router_name:
                    vendor_config = rc.vendor_config
                    break
            if not vendor_config:
                continue

            for remote_as, session in vendor_config.sessions.items():
                if remote_as != self._as_candidate.local_as:
                    continue

                for peering in session.peerings:
                    if peering.local_ip is not None:
                        continue
                    if peering.remote_ip is None:
                        continue

                    remote_ip_str = str(peering.remote_ip)

                    other_name = None
                    other_iface_idx = None
                    for cand_name, cand_ips in router_iface_ips.items():
                        if cand_name == router_name:
                            continue
                        if remote_ip_str in cand_ips:
                            other_name = cand_name
                            other_iface_idx = cand_ips[remote_ip_str]
                            break

                    if other_name is None:
                        continue

                    pair_key = tuple(sorted([router_name, other_name]))
                    if pair_key in connected_pairs:
                        continue

                    router_iface_idx = None
                    local_ip_str = None
                    other_vc = None
                    for rc in self._as_candidate.routers:
                        if rc.router_name == other_name:
                            other_vc = rc.vendor_config
                            break

                    if other_vc:
                        for other_ras, other_sess in other_vc.sessions.items():
                            if other_ras != self._as_candidate.local_as:
                                continue
                            for other_peer in other_sess.peerings:
                                if other_peer.remote_ip is None:
                                    continue
                                o_remote = str(other_peer.remote_ip)
                                if o_remote in router_iface_ips.get(router_name, {}):
                                    router_iface_idx = router_iface_ips[router_name][o_remote]
                                    local_ip_str = o_remote
                                    break
                            if router_iface_idx is not None:
                                break

                    if router_iface_idx is None or local_ip_str is None:
                        logging.warning(
                            f"Cannot find interface on {router_name} for "
                            f"non-DC iBGP to {other_name}"
                        )
                        continue

                    pairs.append((router_name, router_iface_idx, other_name,
                                  other_iface_idx, remote_ip_str, local_ip_str))
                    connected_pairs.add(pair_key)

        if not pairs:
            return

        # Create a single shared collision domain (switch) for all non-DC iBGP
        ibgp_switch_cd = CollisionDomain.get_instance().get(
            f"as{self._as_candidate.local_as}", "ibgp_switch"
        )

        # Connect all pairs through the shared switch CD
        for a_name, a_idx, b_name, b_idx, a_remote, a_local in pairs:
            a_router = candidate_routers[a_name]
            b_router = candidate_routers[b_name]

            a_router._iface_idx_to_cd[a_idx] = ibgp_switch_cd
            b_router._iface_idx_to_cd[b_idx] = ibgp_switch_cd

            a_router.connect_to_neighbour(b_router, a_idx, ibgp_switch_cd)
            b_router.connect_to_neighbour(a_router, b_idx, ibgp_switch_cd)

            logging.info(
                f"Connected {a_name} (eth{a_idx}) <-> {b_name} (eth{b_idx}) "
                f"via iBGP switch CD {ibgp_switch_cd}"
            )

        # Add static routes: each router needs a route for every peer IP
        router_routes: dict[str, list[tuple[str, int]]] = {}
        for a_name, a_idx, b_name, b_idx, a_remote, a_local in pairs:
            if a_name not in router_routes:
                router_routes[a_name] = []
            if b_name not in router_routes:
                router_routes[b_name] = []
            router_routes[a_name].append((a_remote, a_idx))
            router_routes[b_name].append((a_local, b_idx))

        for router_name, routes in router_routes.items():
            router = candidate_routers[router_name]
            for remote_ip, iface_idx in routes:
                route = f"ip route add {remote_ip}/32 dev eth{iface_idx}"
                if route not in router.static_routes:
                    router.static_routes.append(route)
                    logging.info(
                        f"  Route on {router_name} (eth{iface_idx}): "
                        f"ip route add {remote_ip}/32"
                    )

    def _add_dummy_interfaces_candidate_routers(self, candidate_routers: dict) -> None:
        for router in candidate_routers.values():
            if not router.neighbours:
                continue

            max_idx = max(router.neighbours.keys()) if router.neighbours else 0
            for i in range(0, max_idx + 1):
                if i in router.neighbours:
                    continue

                cd = CollisionDomain.get_instance().get(router.machine_name, f"dummy_net_{i}")
                router.connect_interface_to_cd(cd, i)

    def _add_internet_and_providers(self, candidate_routers: dict) -> None:
        providers_routers = [n for n in self._nodes.values() 
                      if isinstance(n, BgpRouter) and n.is_provider() and not n.is_candidate()]
        providers_ases = set(n.identifier for n in providers_routers)

        peering_networks_v4 = ipaddress.ip_network("10.0.0.0/8").subnets(new_prefix=24)
        peering_networks_v6 = ipaddress.ip_network("fc00::/7").subnets(new_prefix=120)

        internet_router = BgpRouter(INTERNET_AS_NUM, -1)
        self._nodes[INTERNET_AS_NUM] = internet_router
        internet_router.add_announced_network(ipaddress.IPv4Network("0.0.0.0/0"))
        internet_router.add_announced_network(ipaddress.IPv6Network("0::0/0"))

        internet_router_client = Client(INTERNET_AS_NUM)
        internet_router.connect_to_neighbour(internet_router_client)
        internet_router_client.connect_to_neighbour(internet_router)

        for provider_router in providers_routers:
            peering_network_v4 = next(peering_networks_v4)
            peering_ips_v4 = peering_network_v4.hosts()
            peering_prefixlen_v4 = peering_network_v4.prefixlen

            peering_network_v6 = next(peering_networks_v6)
            peering_ips_v6 = peering_network_v6.hosts()
            peering_prefixlen_v6 = peering_network_v6.prefixlen

            provider_originated_networks = self._get_originated_networks_by_as_num(provider_router.identifier)
            for net in provider_originated_networks:
                provider_router.add_local_network(net)
                provider_router.add_announced_network(net)
            utils.aggregate_v4_6_networks(provider_router.local_networks)

            internet_iface_idx = internet_router.connect_to_neighbour(provider_router)
            internet_router.add_local_iface_ip(
                internet_iface_idx, provider_router,
                ipaddress.ip_interface(f"{next(peering_ips_v4)}/{peering_prefixlen_v4}"),
                is_public=True
            )
            internet_router.add_local_iface_ip(
                internet_iface_idx, provider_router,
                ipaddress.ip_interface(f"{next(peering_ips_v6)}/{peering_prefixlen_v6}"),
                is_public=True
            )

            provider_iface_idx = provider_router.connect_to_neighbour(internet_router)
            provider_router.add_local_iface_ip(
                provider_iface_idx, internet_router,
                ipaddress.ip_interface(f"{next(peering_ips_v4)}/{peering_prefixlen_v4}"),
                is_public=True
            )
            provider_router.add_local_iface_ip(
                provider_iface_idx, internet_router,
                ipaddress.ip_interface(f"{next(peering_ips_v6)}/{peering_prefixlen_v6}"),
                is_public=True
            )

            neighbour_client = Client(provider_router.identifier)
            neighbour_client.connect_to_neighbour(provider_router)
            provider_router.connect_to_neighbour(neighbour_client)

        for rc in self._as_candidate.routers:
            router = candidate_routers[rc.router_name]
            candidate_router_client = Client(self._as_candidate.local_as, router.machine_name)

            # Interfaces already used for eBGP peering.
            used_iface_idxs = set()
            if rc.vendor_config:
                for remote_as, session in rc.vendor_config.sessions.items():
                    if remote_as != self._as_candidate.local_as and session.iface_idx is not None:
                        used_iface_idxs.add(session.iface_idx)

            # Find a public-network interface that is not already used for eBGP peering.
            public_iface_candidates = []
            if rc.vendor_config:
                for iface_name, iface in rc.vendor_config.interfaces.items():
                    iface_real_name = iface.phy.name if hasattr(iface, 'phy') else iface.name
                    if iface_real_name not in rc.vendor_config.iface_to_iface_idx:
                        continue
                    iface_idx = rc.vendor_config.iface_to_iface_idx[iface_real_name]
                    if iface_idx in used_iface_idxs:
                        continue
                    for addr in iface.addresses:
                        if not addr.network.is_private and not addr.network.is_loopback:
                            if iface_idx in router.neighbours:
                                public_iface_candidates.append(iface_idx)
                            break

            logging.info(f"Router {router.machine_name} - public_iface_candidates: {public_iface_candidates}")

            # Randomly choose among the public interfaces.
            client_iface_idx = -1
            if public_iface_candidates:
                client_iface_idx = random.choice(public_iface_candidates)
            else:
                logging.warning(f"No public network found on {router.machine_name}, using first empty interface.")
                for iface_idx in router.neighbours:
                    if not router.neighbours[iface_idx]:
                        client_iface_idx = iface_idx
                        break

            if client_iface_idx != -1:
                cd = router.get_cd_by_iface_idx(client_iface_idx)
                router.connect_to_neighbour(candidate_router_client, client_iface_idx)
                candidate_router_client.connect_to_neighbour_by_cd(router, cd)
                logging.info(f"Connected client to {router.machine_name} on iface {client_iface_idx} (CD: {cd}).")
            else:
                logging.warning(f"No interface available for client on {router.machine_name}, Creating new one.")
                if self._as_candidate:
                    self._as_candidate.routers_needing_client.add(router.machine_name)

    def _infer_bgp_relationships(self) -> None:
        logging.info("Inferring BGP relationships...")

        (import_rules, _) = RipeDb.get_instance().get_local_as_rules(self._vendor_config.local_as)

        import_rules = set([" ".join(x.split(' ')[2:]) if 'afi' in x else x for x in import_rules])

        for remote_as_num, session in self._vendor_config.sessions.items():
            found = False
            
            local_rel = RipeDb.get_instance().get_local_relationship(self._vendor_config.local_as, remote_as_num)
            if local_rel is not None:
                session.relationship = local_rel
                rel_name = {0: "peer", 1: "provider", 2: "customer"}.get(local_rel, "unknown")
                logging.info(f"Found LOCAL relationship AS{self._vendor_config.local_as} -> AS{remote_as_num}: {rel_name} ({local_rel}).")
                found = True
            
            if not found:
                rule_pattern = f"from AS{remote_as_num}"
                for rule in import_rules:
                    if rule_pattern in rule:
                        found = True

                        if 'any' in rule.lower():
                            session.relationship = 1
                        else:
                            session.relationship = 2

                        logging.info(f"Found RIPE relationship {rule_pattern}: {session.relationship}.")
                        break

            if not found:
                logging.warning(f"Cannot find relationship for AS{remote_as_num}, putting it as peer (0).")
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

    def get_candidate_routers(self) -> list[BgpRouter]:
        return [node for node in self._nodes.values() if isinstance(node, BgpRouter) and node.candidate]

    def get_candidate_router_config(self, machine_name: str) -> VendorConfiguration | None:
        if self._as_candidate:
            for rc in self._as_candidate.routers:
                if rc.machine_name == machine_name:
                    return rc.vendor_config
        return None

    def get_candidate_router_startup(self, machine_name: str) -> str | None:
        if self._as_candidate:
            for rc in self._as_candidate.routers:
                if rc.machine_name == machine_name:
                    return rc.startup_script_path
        return None

    def get(self, identifier: int | str) -> Node:
        if identifier in self._nodes:
            return self._nodes[identifier]
        
        for node in self._nodes.values():
            if node.identifier == identifier:
                return node
        
        raise TopologyError(f"Node {identifier} not found in topology")
