import ipaddress
import logging
import shlex
import time

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.model.Machine import Machine

from ..model.as_candidate import AsCandidate
from . import action_utils
from .. import utils
from ..foundation.actions.action import Action
from ..foundation.actions.action_result import ActionResult, WARNING, SUCCESS, ERROR
from ..foundation.configuration.vendor_configuration import VendorConfiguration
from ..model.topology import Topology
from ..mrt.table_dump import TableDump


class RouteLeakAction(Action):
    def verify(
        self, as_candidate: AsCandidate, table_dump: TableDump, topology: Topology | None = None,
        net_scenario: Lab | None = None
    ) -> ActionResult:
        action_result = ActionResult(self)

        providers_routers = list(filter(lambda x: x[1].is_provider() and not x[1].is_candidate(), topology.all()))
        if len(providers_routers) == 0:
            logging.warning("No providers found, skipping check...")
            action_result.add_result(WARNING, "No providers found.")
            return action_result

        all_announced_networks = {4: set(), 6: set()}
        for _, provider in providers_routers:
            logging.info(f"Reading networks from provider AS{provider.identifier}...")
            device_networks = action_utils.get_bgp_networks(net_scenario.get_machine(provider.machine_name))
            all_announced_networks[4].update(device_networks[4])
            all_announced_networks[6].update(device_networks[6])

        all_announced_networks[4] = set(filter(lambda x: x.prefixlen != 0, all_announced_networks[4]))
        all_announced_networks[6] = set(filter(lambda x: x.prefixlen != 0, all_announced_networks[6]))

        logging.info("Aggregating networks...")
        utils.aggregate_v4_6_networks(all_announced_networks)
        logging.debug(f"Resulting networks are: {all_announced_networks}")

        # Collect customers from NeighborInfo
        customers = {
            neighbor_as: neighbor_info
            for neighbor_as, neighbor_info in as_candidate.neighbors.items()
            if neighbor_info.neighbor_type == 2
        }

        if not customers:
            logging.warning("No customers found, skipping check...")
            action_result.add_result(WARNING, "No customers found.")
            return action_result

        for v, networks in all_announced_networks.items():
            logging.info(f"Performing check on IPv{v}...")

            if not networks:
                logging.warning(f"No networks announced in IPv{v}, skipping...")
                action_result.add_result(WARNING, f"No networks announced in IPv{v}.")
                continue

            spoofing_net = action_utils.get_non_overlapping_network(v, networks)
            logging.info(f"Chosen network to announce is {spoofing_net}.")

            for neighbor_as, neighbor_info in customers.items():
                logging.info(f"Processing customer AS{neighbor_as}, peerings: {neighbor_info.peerings}")
                customer_node = topology.get(neighbor_as)
                customer_device = net_scenario.get_machine(customer_node.machine_name)

                for border_router_machine_name, peering_ips in neighbor_info.peerings.items():
                    if v not in peering_ips:
                        logging.warning(
                            f"No IPv{v} peering between AS{neighbor_as} and {border_router_machine_name}, skipping..."
                        )
                        action_result.add_result(
                            WARNING,
                            f"No networks announced in IPv{v} from customer AS{neighbor_as} "
                            f"towards {border_router_machine_name}."
                        )
                        continue

                    router = as_candidate.get_router_by_machine_name(border_router_machine_name)
                    candidate_device = net_scenario.get_machine(border_router_machine_name)

                    # Announce spoofed network from customer
                    self._vtysh_network(customer_device, neighbor_as, spoofing_net)

                    # Find the customer's peering IP towards the candidate (candidate side).
                    candidate_topo_node = topology.get(border_router_machine_name)
                    customer_neigh, _ = candidate_topo_node.get_neighbour_by_name(customer_node.name)
                    if not customer_neigh:
                        logging.warning(
                            f"Cannot find customer AS{neighbor_as} on {border_router_machine_name}, skipping..."
                        )
                        self._no_vtysh_network(customer_device, neighbor_as, spoofing_net)
                        continue

                    customer_neigh_ips = customer_neigh.get_neighbours_ips(is_public=True)
                    customer_peering_ip = action_utils.get_active_neighbour_peering_ip(
                        candidate_device, router.vendor_config, customer_neigh_ips[v], vendor=True
                    )

                    if not customer_peering_ip:
                        logging.warning(
                            f"No peering on IPv{v} between AS{neighbor_as} and {border_router_machine_name}, skipping..."
                        )
                        action_result.add_result(
                            WARNING,
                            f"No peering on IPv{v} between AS{neighbor_as} and {border_router_machine_name}."
                        )
                        self._no_vtysh_network(customer_device, neighbor_as, spoofing_net)
                        continue

                    max_attempts = 15
                    attempt = 0
                    network_received = False
                    while attempt < max_attempts:
                        time.sleep(2)
                        customer_cand_nets = self._vendor_get_neighbour_bgp_networks(
                            candidate_device, router.vendor_config, customer_peering_ip.ip
                        )
                        if spoofing_net in customer_cand_nets:
                            logging.info(f"Network {spoofing_net} received by {border_router_machine_name}.")
                            network_received = True
                            break
                        attempt += 1

                    if not network_received:
                        logging.warning(
                            f"Network {spoofing_net} never received by {border_router_machine_name} "
                            f"from customer AS{neighbor_as}, skipping..."
                        )
                        action_result.add_result(
                            WARNING,
                            f"Network {spoofing_net} never received by {border_router_machine_name} "
                            f"from customer AS{neighbor_as}."
                        )
                        self._no_vtysh_network(customer_device, neighbor_as, spoofing_net)
                        continue

                    # Check whether the candidate propagates the network towards the providers.
                    for _, provider in providers_routers:
                        logging.info(f"Checking provider AS{provider.identifier} for border router {border_router_machine_name}")
                        logging.debug(f"provider_neighbor_info: {as_candidate.neighbors.get(provider.identifier)}")
                        provider_node = topology.get(provider.identifier)
                        provider_device = net_scenario.get_machine(provider_node.machine_name)

                        provider_neighbor_info = as_candidate.neighbors.get(provider.identifier)
                        if not provider_neighbor_info:
                            logging.warning(f"AS{provider.identifier} not in neighbor map, skipping...")
                            continue

                        # Find any border router peering with this provider.
                        provider_peerings = {
                            br: ips for br, ips in provider_neighbor_info.peerings.items()
                            if v in ips
                        }

                        if not provider_peerings:
                            logging.warning(
                                f"No IPv{v} peering between any border router and AS{provider.identifier}, skipping..."
                            )
                            action_result.add_result(
                                WARNING,
                                f"No peering on IPv{v} between AS{provider.identifier} and any border router."
                            )
                            continue

                        for provider_border_router, provider_ips in provider_peerings.items():
                            for cand_peering_ip in provider_ips[v]:
                                candidate_nets = action_utils.get_neighbour_bgp_networks(provider_device, cand_peering_ip.ip)
                                result = spoofing_net not in candidate_nets

                                if result:
                                    msg = (f"Configuration correctly blocks announcements of the spoofed network "
                                        f"{spoofing_net} of customer AS{neighbor_as} towards provider "
                                        f"AS{provider.identifier} via {provider_border_router}.")
                                else:
                                    msg = (f"Configuration allows to announce the spoofed network {spoofing_net} of "
                                        f"customer AS{neighbor_as} towards provider AS{provider.identifier} "
                                        f"via {provider_border_router}.")
                                action_result.add_result(SUCCESS if result else ERROR, msg)

                    self._no_vtysh_network(customer_device, neighbor_as, spoofing_net)

        return action_result

    @staticmethod
    def _vtysh_network(device: Machine, as_num: int, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
        logging.info(f"Announcing Network={net} in device `{device.name}`.")

        v = net.version
        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split(f"vtysh "
                                f"-c 'configure' "
                                f"-c 'router bgp {as_num}' "
                                f"-c 'address-family ipv{v} unicast' "
                                f"-c 'network {net}' "
                                f"-c 'exit' -c 'exit' -c 'exit'"),
            lab_name=device.lab.name
        )

        # Triggers the command.
        try:
            next(exec_output)
        except StopIteration:
            pass

    @staticmethod
    def _no_vtysh_network(device: Machine, as_num: int, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
        logging.info(f"Removing Network={net} announcement in device `{device.name}`.")

        v = net.version
        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split(f"vtysh "
                                f"-c 'configure' "
                                f"-c 'router bgp {as_num}' "
                                f"-c 'address-family ipv{v} unicast' "
                                f"-c 'no network {net}' "
                                f"-c 'exit' -c 'exit' -c 'exit'"),
            lab_name=device.lab.name
        )

        # Triggers the command.
        try:
            next(exec_output)
        except StopIteration:
            pass

    @staticmethod
    def _vendor_get_neighbour_bgp_networks(device: Machine, config: VendorConfiguration,
                                           neighbour_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> set:
        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split(config.command_get_neighbour_bgp_networks(neighbour_ip)),
            lab_name=device.lab.name
        )
        output = ""
        try:
            while True:
                (stdout, _) = next(exec_output)
                stdout = stdout.decode('utf-8') if stdout else ""

                if stdout:
                    output += stdout
        except StopIteration:
            pass

        return config.parse_bgp_routes(output)

    def name(self) -> str:
        return "leak"

    def display_name(self) -> str:
        return "Route Leak Check"
