import ipaddress
import logging
import shlex
import time

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.model.Machine import Machine

from . import action_utils
from .. import utils
from ..foundation.actions.action import Action
from ..foundation.actions.action_result import ActionResult, WARNING, SUCCESS, ERROR
from ..foundation.configuration.vendor_configuration import VendorConfiguration
from ..model.topology import Topology
from ..mrt.table_dump import TableDump


class RouteLeakAction(Action):
    def verify(
            self, config: VendorConfiguration, table_dump: TableDump, topology: Topology | None = None,
            net_scenario: Lab | None = None
    ) -> ActionResult:
        action_result = ActionResult(self)

        candidate = topology.get(config.local_as)
        candidate_device = net_scenario.get_machine(candidate.name)

        all_announced_networks = {4: set(), 6: set()}
        # Get all providers
        providers_routers = list(filter(lambda x: x[1].is_provider(), topology.all()))
        if len(providers_routers) == 0:
            logging.warning("No providers found, skipping check...")
            action_result.add_result(WARNING, "No providers found.")
            return action_result

        for _, provider in providers_routers:
            logging.info(f"Reading networks from provider AS{provider.identifier}...")
            device_networks = action_utils.get_bgp_networks(net_scenario.get_machine(provider.name))
            all_announced_networks[4].update(device_networks[4])
            all_announced_networks[6].update(device_networks[6])

        # Remove default
        all_announced_networks[4] = set(filter(lambda x: x.prefixlen != 0, all_announced_networks[4]))
        all_announced_networks[6] = set(filter(lambda x: x.prefixlen != 0, all_announced_networks[6]))

        logging.info("Aggregating networks...")
        utils.aggregate_v4_6_networks(all_announced_networks)
        logging.debug(f"Resulting networks are: {all_announced_networks}")

        customer_routers = list(
            filter(
                lambda x: x[1].is_customer() and x[1].get_neighbour_by_name(candidate.name)[0] is not None,
                topology.all()
            )
        )
        if len(customer_routers) == 0:
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

            for _, customer in customer_routers:
                candidate_neighbour, _ = customer.get_neighbour_by_name(candidate.name)

                candidate_ips = candidate_neighbour.get_neighbours_ips(is_public=True)
                if len(candidate_ips[v]) == 0:
                    logging.warning(f"No networks announced in IPv{v} from "
                                    f"customer AS{customer.identifier} towards candidate AS, skipping...")
                    action_result.add_result(WARNING, f"No networks announced in IPv{v} from "
                                                      f"customer AS{customer.identifier} towards candidate AS.")
                    continue

                customer_device = net_scenario.get_machine(customer.name)

                # Announce the spoofed network from the customer
                self._vtysh_network(customer_device, customer.identifier, spoofing_net)
                customer_neigh, _ = candidate.get_neighbour_by_name(customer.name)
                customer_neigh_ips = customer_neigh.get_neighbours_ips(is_public=True)

                customer_peering_ip = action_utils.get_active_neighbour_peering_ip(
                    candidate_device, config, customer_neigh_ips[v], vendor=True
                )
                if not customer_peering_ip:
                    logging.warning(f"No peering on IPv{v} between AS{customer.identifier} and candidate, skipping...")
                    action_result.add_result(
                        WARNING, f"No peering on IPv{v} between AS{customer.identifier} and candidate."
                    )

                    self._no_vtysh_network(customer_device, customer.identifier, spoofing_net)

                    continue

                while True:
                    time.sleep(2)
                    customer_cand_nets = self._vendor_get_neighbour_bgp_networks(
                        candidate_device, config, customer_peering_ip.ip
                    )
                    if spoofing_net in customer_cand_nets:
                        logging.info(f"Network {spoofing_net} received by candidate AS.")
                        break

                for _, provider in providers_routers:
                    provider_device = net_scenario.get_machine(provider.name)

                    candidate_neigh, _ = provider.get_neighbour_by_name(candidate.name)
                    candidate_neigh_ips = candidate_neigh.get_neighbours_ips(is_public=True)

                    cand_peering_ip = action_utils.get_active_neighbour_peering_ip(
                        provider_device, config, candidate_neigh_ips[v], vendor=False
                    )
                    if not cand_peering_ip:
                        logging.warning(
                            f"No peering on IPv{v} between AS{provider.identifier} and candidate, skipping..."
                        )
                        action_result.add_result(
                            WARNING, f"No peering on IPv{v} between AS{provider.identifier} and candidate."
                        )
                        continue

                    candidate_nets = action_utils.get_neighbour_bgp_networks(provider_device, cand_peering_ip.ip)
                    result = spoofing_net not in candidate_nets
                    if result:
                        msg = f"Configuration correctly blocks announcements of the spoofed network {spoofing_net} " \
                              f"of customer AS{customer.identifier} towards provider AS{provider.identifier}."
                    else:
                        msg = f"Configuration allows to announce the spoofed network {spoofing_net} of " \
                              f"customer AS{customer.identifier} towards provider AS{provider.identifier}."
                    action_result.add_result(SUCCESS if result else ERROR, msg)

                self._no_vtysh_network(customer_device, customer.identifier, spoofing_net)

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
