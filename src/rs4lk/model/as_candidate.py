from typing import OrderedDict
from .router_candidate import RouterCandidate
import itertools
import logging
from Kathara.model.Lab import Lab
from .neighbor_info import NeighborInfo
from ..model.topology import Topology
from ..actions import action_utils


class AsCandidate:
    __slots__ = ['local_as', 'routers', '_routers_by_name', 'neighbors', 'assigned_ips', 'relationships_path', 'rib_dump_path', 'routers_needing_client']

    def __init__(self, local_as: int, relationships_path: str | None = None, rib_dump_path: str | None = None) -> None:
        self.local_as: int = local_as
        self.routers: list[RouterCandidate] = []
        self._routers_by_name: dict[str, RouterCandidate] = {}
        self.neighbors: dict[int, NeighborInfo] = {}  # neighbor_as -> NeighborInfo
        self.assigned_ips: set = set()
        self.relationships_path: str | None = relationships_path
        self.rib_dump_path: str | None = rib_dump_path
        self.routers_needing_client: set[str] = set()

    def add_router(self, router: RouterCandidate) -> None:
        if router.identifier != self.local_as:
            raise ValueError(f"Router {router.router_name} has AS {router.identifier}, expected {self.local_as}")
        if router.router_name in self._routers_by_name:
            raise ValueError(f"Router with name {router.router_name} already exists in AS {self.local_as}")
        self.routers.append(router)
        self._routers_by_name[router.router_name] = router

    def get_router(self, name: str) -> RouterCandidate | None:
        return self._routers_by_name.get(name)

    def build_neighbor_map(self, topology: Topology, net_scenario: Lab) -> None:
        logging.info(f"Building neighbor map for AS{self.local_as}...")

        # Collect all assigned IP addresses from all border routers.
        self.assigned_ips = set()
        for router in self.routers:
            if not router.vendor_config:
                continue
            for iface in router.vendor_config.interfaces.values():
                self.assigned_ips.update(iface.addresses)

        for router in self.routers:
            if not router.vendor_config:
                continue

            logging.info(f"Processing router {router.machine_name}...")
            router_device = net_scenario.get_machine(router.machine_name)

            for remote_as, session in router.vendor_config.sessions.items():
                # Skip iBGP sessions.
                if remote_as == self.local_as:
                    continue

                if not session.iface:
                    logging.warning(f"Session with AS{remote_as} on {router.machine_name} has no interface, skipping...")
                    continue

                # Retrieve the node from the topology.
                try:
                    neighbor_node = topology.get(remote_as)
                except Exception:
                    logging.warning(f"AS{remote_as} not found in topology, skipping...")
                    continue

                neighbor_device = net_scenario.get_machine(neighbor_node.machine_name)

                # Create or retrieve the NeighborInfo for this AS.
                if remote_as not in self.neighbors:
                    self.neighbors[remote_as] = NeighborInfo(
                        neighbor_as=remote_as,
                        neighbor_type=session.relationship
                    )

                neighbor_info = self.neighbors[remote_as]
                neighbor_info.add_peering(router.machine_name)

                # Iterate over every peering in the session.
                for peering in session.peerings:
                    if peering.local_ip is None:
                        continue

                    v = peering.local_ip.version

                    cand_peering_ip = peering.local_ip
                    
                    networks = action_utils.get_neighbour_bgp_networks(neighbor_device, cand_peering_ip.ip)
                    neighbor_info.add_peering_ip(router.machine_name, v, cand_peering_ip)
                    neighbor_info.add_announced_networks(router.machine_name, v, networks)

                    logging.info(
                        f"AS{remote_as} <-> {router.machine_name} IPv{v}: "
                        f"peering_ip={cand_peering_ip}, networks={networks}"
                    )

        logging.debug(f"Neighbor map built: {self.neighbors}")

    def get_router_by_machine_name(self, machine_name: str) -> RouterCandidate | None:
        for router in self.routers:
            if router.machine_name == machine_name:
                return router
        return None
    
    def __repr__(self) -> str:
        return f"AsCandidate AS{self.local_as} ({len(self.routers)} routers: {[r.router_name for r in self.routers]})"
