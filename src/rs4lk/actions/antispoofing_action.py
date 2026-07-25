import ipaddress
import itertools
import logging
import os
import random
import shlex
import time
from io import BytesIO

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.model.Machine import Machine

from ..model.as_candidate import AsCandidate
from . import action_utils
from .. import utils
from ..foundation.actions.action import Action
from ..foundation.actions.action_result import ActionResult, WARNING, SUCCESS, ERROR
from ..foundation.configuration.vendor_configuration import VendorConfiguration
from ..globals import RESOURCES_FOLDER
from ..model.topology import Topology, INTERNET_AS_NUM
from ..mrt.table_dump import TableDump


class AntiSpoofingAction(Action):
    def verify(
        self, as_candidate: AsCandidate, table_dump: TableDump, topology: Topology | None = None,
        net_scenario: Lab | None = None
    ) -> ActionResult:
        action_result = ActionResult(self)

        providers = {
            neighbor_as: neighbor_info
            for neighbor_as, neighbor_info in as_candidate.neighbors.items()
            if neighbor_info.neighbor_type == 1
        }

        if not providers:
            logging.warning("No providers found, skipping check...")
            action_result.add_result(WARNING, "No providers found.")
            return action_result

        all_announced_networks = {4: set(), 6: set()}
        providers_routers = list(filter(lambda x: x[1].is_provider() and not x[1].is_candidate(), topology.all()))
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

        # Compute all candidate announced networks for both IP versions (used by all routers)
        all_candidate_nets_to_providers = {4: set(), 6: set()}
        for ni in as_candidate.neighbors.values():
            if ni.neighbor_type != 1:
                continue
            for br_nets in ni.announced_networks.values():
                all_candidate_nets_to_providers[4].update(br_nets[4])
                all_candidate_nets_to_providers[6].update(br_nets[6])
        utils.aggregate_v4_6_networks(all_candidate_nets_to_providers)

        # Set up dynamic client containers for routers that lack a client interface
        dynamic_clients: dict[str, dict] = {}
        for router in as_candidate.routers:
            if router.machine_name not in as_candidate.routers_needing_client:
                continue
            border_name = router.machine_name
            picked_nets = {}
            for v in (4, 6):
                addr_len = 32 if v == 4 else 128
                # Only networks announced by this specific router towards the provider.
                router_nets = set()
                for ni in as_candidate.neighbors.values():
                    if ni.neighbor_type != 1:
                        continue
                    if border_name in ni.announced_networks:
                        router_nets.update(ni.announced_networks[border_name][v])
                router_nets = utils.aggregate_networks(router_nets)
                nets_list = list(router_nets)
                if not nets_list:
                    continue
                random.shuffle(nets_list)
                for net in nets_list:
                    if (2 ** (addr_len - net.prefixlen)) - 2 > 2:
                        picked_nets[v] = net
                        break
            if not picked_nets:
                logging.warning(f"No viable networks for dynamic client on {border_name}, skipping.")
                continue
            logging.info(f"Selected networks {picked_nets} for dynamic client on {border_name}.")
            dc = self._setup_dynamic_client(
                router, net_scenario, picked_nets, as_candidate.assigned_ips
            )
            dynamic_clients[border_name] = dc

        for v, networks in all_announced_networks.items():
            logging.info(f"Performing check on IPv{v}...")
            addr_len = 32 if v == 4 else 128

            if not networks:
                logging.warning(f"No networks announced in IPv{v}, skipping...")
                action_result.add_result(WARNING, f"No networks announced in IPv{v}.")
                continue

            default_net = ipaddress.IPv4Network("0.0.0.0/0") if v == 4 else ipaddress.IPv6Network("::/0")

            spoofing_net = action_utils.get_non_overlapping_network(v, networks)
            logging.info(f"Chosen network to spoof is {spoofing_net}.")
            spoofing_hosts = spoofing_net.hosts()

            logging.info(f"Setting IPv{v} addresses on AS{INTERNET_AS_NUM} (Internet)...")
            internet_router = topology.get(INTERNET_AS_NUM)
            internet_router_client_name = f"as{INTERNET_AS_NUM}_client"
            _, internet_router_client_iface_idx = internet_router.get_node_by_name(internet_router_client_name)
            internet_router_device = net_scenario.get_machine(internet_router.machine_name)
            internet_router_ip = ipaddress.ip_interface(f"{next(spoofing_hosts)}/{spoofing_net.prefixlen}")
            self._ip_addr_add(internet_router_device, internet_router_client_iface_idx, internet_router_ip)

            spoofed_src_ip = next(spoofing_hosts)
            internet_router_client = net_scenario.get_machine(internet_router_client_name)
            internet_router_client_ip = ipaddress.ip_interface(f"{spoofed_src_ip}/{spoofing_net.prefixlen}")
            self._ip_addr_add(internet_router_client, 0, internet_router_client_ip)
            self._ip_route_add(internet_router_client, default_net, internet_router_ip.ip, 0)

            for neighbor_as, neighbor_info in providers.items():
                provider = topology.get(neighbor_as)
                provider_device = net_scenario.get_machine(provider.machine_name)

                if len(provider.local_networks[v]) == 0:
                    logging.warning(f"AS{neighbor_as} does not announce networks in IPv{v}, skipping...")
                    action_result.add_result(WARNING, f"AS{neighbor_as} does not announce networks in IPv{v}.")
                    continue

                provider_net = None
                provider_local_nets = list(filter(
                    lambda x: x.prefixlen != 0, 
                    provider.local_networks[v]
                ))

                while len(provider_local_nets) > 0:
                    rand_idx = random.randint(0, len(provider_local_nets) - 1)
                    provider_net_rand = provider_local_nets.pop(rand_idx)
                    if (2 ** (addr_len - provider_net_rand.prefixlen)) - 2 > 5:
                        provider_net = provider_net_rand
                        break

                if provider_net is None:
                    logging.warning(f"No viable IPv{v} networks on AS{neighbor_as}, skipping...")
                    action_result.add_result(WARNING, f"No viable IPv{v} networks on AS{neighbor_as}.")
                    continue

                logging.info(f"Selected network {provider_net} on AS{neighbor_as}.")
                provider_net_hosts = provider_net.hosts()

                provider_client_name = f"as{neighbor_as}_client"
                _, provider_client_iface_idx = provider.get_node_by_name(provider_client_name)
                provider_ip = ipaddress.ip_interface(f"{next(provider_net_hosts)}/{provider_net.prefixlen}")
                self._ip_addr_add(provider_device, provider_client_iface_idx, provider_ip)

                provider_client_addr = next(provider_net_hosts)
                provider_client = net_scenario.get_machine(provider_client_name)
                provider_client_ip = ipaddress.ip_interface(f"{provider_client_addr}/{provider_net.prefixlen}")
                self._ip_addr_add(provider_client, 0, provider_client_ip)
                self._ip_route_add(provider_client, default_net, provider_ip.ip, 0)

                for router in as_candidate.routers:
                    border_router_machine_name = router.machine_name
                    candidate_topo_node = topology.get(border_router_machine_name)
                    candidate_device = net_scenario.get_machine(border_router_machine_name)

                    dc = dynamic_clients.get(border_router_machine_name)
                    if dc is not None and f'client_ip_v{v}' in dc:
                        candidate_client = dc['client_device']
                        candidate_client_name = dc['client_name']
                        candidate_client_iface_idx = dc['router_iface_idx']
                        candidate_client_ip = dc[f'client_ip_v{v}']
                        candidate_ip = dc[f'router_ip_v{v}']
                    else:
                        candidate_client_name = f"{border_router_machine_name}_client"
                        _, candidate_client_iface_idx = candidate_topo_node.get_node_by_name(candidate_client_name)

                        if candidate_client_iface_idx == -1:
                            logging.warning(f"No client interface available for {border_router_machine_name}, skipping...")
                            action_result.add_result(
                                WARNING,
                                f"No client available for {border_router_machine_name}, cannot perform anti-spoofing check."
                            )
                            continue

                        candidate_client = net_scenario.get_machine(candidate_client_name)

                        client_iface_nets = set()
                        if router.vendor_config:
                            for iface_name, iface in router.vendor_config.interfaces.items():
                                iface_real_name = iface.phy.name if hasattr(iface, 'phy') else iface.name
                                if router.vendor_config.iface_to_iface_idx.get(iface_real_name) == candidate_client_iface_idx:
                                    for addr in iface.addresses:
                                        if addr.version == v:
                                            client_iface_nets.add(addr.network)
                        logging.info(f"Client interface {candidate_client_iface_idx} on {border_router_machine_name} has networks: {client_iface_nets}")

                        candidate_nets = {
                            net for net in all_candidate_nets_to_providers[v]
                            if any(net.overlaps(n) for n in client_iface_nets)
                        }

                        if not candidate_nets:
                            logging.warning(
                                f"No viable networks on client interface for {border_router_machine_name}, skipping..."
                            )
                            action_result.add_result(
                                WARNING, f"No viable networks for {border_router_machine_name} on IPv{v}."
                            )
                            continue

                        candidate_net = None
                        candidate_local_nets = list(candidate_nets)
                        while len(candidate_local_nets) > 0:
                            rand_idx = random.randint(0, len(candidate_local_nets) - 1)
                            candidate_net_rand = candidate_local_nets.pop(rand_idx)
                            iface_net = next(
                                (n for n in client_iface_nets if candidate_net_rand.overlaps(n)),
                                None
                            )
                            if iface_net is None:
                                continue
                            if (2 ** (addr_len - iface_net.prefixlen)) - 2 > 2:
                                candidate_net = candidate_net_rand
                                break
                            else:
                                logging.warning(f"Interface network {iface_net} for {candidate_net_rand} has less than 3 IP addresses.")

                        if candidate_net is None:
                            logging.warning(f"No viable IPv{v} networks on {border_router_machine_name}, skipping...")
                            action_result.add_result(WARNING, f"No viable IPv{v} networks on {border_router_machine_name}.")
                            continue

                        logging.info(f"Selected network {candidate_net} on {border_router_machine_name}.")

                        iface_net = next(n for n in client_iface_nets if candidate_net.overlaps(n))
                        candidate_client_ip = self._get_non_overlapping_address(iface_net, as_candidate.assigned_ips)
                        candidate_ip = self._get_non_overlapping_address(
                            iface_net, as_candidate.assigned_ips.union({candidate_client_ip})
                        )

                        self._ip_addr_add(candidate_client, 0, candidate_client_ip)
                        self._ip_route_add(candidate_client, default_net, candidate_ip.ip, 0)
                        self._vendor_ip_add(candidate_device, router.vendor_config, candidate_client_iface_idx, candidate_ip)

                    logging.info(f"Copying spoofing check script into candidate client `{candidate_client_name}`...")
                    with open(os.path.join(RESOURCES_FOLDER, "host_spoof_check.py"), "rb") as py_script:
                        content = BytesIO(py_script.read())
                    Kathara.get_instance().update_lab_from_api(net_scenario)
                    Kathara.get_instance().copy_files(candidate_client, {'/host_spoof_check.py': content})

                    logging.info(f"Copying sniffer script into client `{internet_router_client_name}`...")
                    with open(os.path.join(RESOURCES_FOLDER, "host_sniffer.py"), "rb") as py_script:
                        content = BytesIO(py_script.read())
                    Kathara.get_instance().update_lab_from_api(net_scenario)
                    Kathara.get_instance().copy_files(internet_router_client, {'/host_sniffer.py': content})

                    logging.info("Waiting 20s before performing check...")
                    time.sleep(20)
                    spoof_passed, sniff_passed = self._perform_spoofing_check(
                        candidate_client, internet_router_client,
                        candidate_client_ip.ip, spoofed_src_ip, provider_client_addr
                    )
                    if spoof_passed and sniff_passed:
                        msg = (f"Configuration correctly blocks a spoofed packet from network {spoofing_net} "
                            f"towards provider AS{neighbor_as} via {border_router_machine_name}. "
                            f"The packet transmitted was SrcIP={spoofed_src_ip} -> DstIP={provider_client_addr}.")
                    else:
                        if not sniff_passed:
                            msg = (f"Configuration allows to send a spoofed packet from network {spoofing_net} "
                                f"towards provider AS{neighbor_as} via {border_router_machine_name}. "
                                f"The packet transmitted was SrcIP={spoofed_src_ip} -> DstIP={provider_client_addr}.")
                        else:
                            msg = (f"The legitimate packet from {border_router_machine_name} did not reach "
                                f"provider AS{neighbor_as}. This suggests that the candidate configuration "
                                f"may be blocking legitimate traffic"
                                f"SrcIP={candidate_client_ip.ip} -> DstIP={provider_client_addr}.")
                    action_result.add_result(SUCCESS if (spoof_passed and sniff_passed) else ERROR, msg)

                    if dc is not None:
                        self._ip_addr_del(candidate_client, 0, candidate_client_ip)
                        self._ip_route_del(candidate_client, default_net, candidate_ip.ip, 0)
                        self._ip_addr_del(candidate_device, candidate_client_iface_idx, candidate_ip)
                    else:
                        self._vendor_ip_del(candidate_device, router.vendor_config, candidate_client_iface_idx, candidate_ip)
                        self._ip_addr_del(candidate_client, 0, candidate_client_ip)
                        self._ip_route_del(candidate_client, default_net, candidate_ip.ip, 0)

                self._cleanup_provider_ips(
                    provider_device, provider_client_iface_idx, provider_ip,
                    provider_client, provider_client_ip, default_net
                )

            self._ip_addr_del(internet_router_device, internet_router_client_iface_idx, internet_router_ip)
            self._ip_addr_del(internet_router_client, 0, internet_router_client_ip)
            self._ip_route_del(internet_router_client, default_net, internet_router_ip.ip, 0)

        for border_name, dc in dynamic_clients.items():
            self._cleanup_dynamic_client(dc, net_scenario)

        return action_result

    def _cleanup_provider_ips(self, provider_device: Machine,
                              provider_client_iface_idx: int,
                              provider_ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface,
                              provider_client: Machine,
                              provider_client_ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface,
                              default_net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
        self._ip_addr_del(provider_device, provider_client_iface_idx, provider_ip)
        self._ip_addr_del(provider_client, 0, provider_client_ip)
        self._ip_route_del(provider_client, default_net, provider_ip.ip, 0)

    @staticmethod
    def _get_non_overlapping_address(network: ipaddress.IPv4Network | ipaddress.IPv6Network,
                                     assigned_ips: set[ipaddress.IPv4Interface | ipaddress.IPv6Interface]
                                     ) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface:
        net_hosts = network.hosts()

        while True:
            selected_ip_iface = ipaddress.ip_interface(f"{next(net_hosts)}/{network.prefixlen}")

            if selected_ip_iface not in assigned_ips:
                break

        return selected_ip_iface

    @staticmethod
    def _ip_addr_add(device: Machine, iface_idx: int, ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> None:
        logging.info(f"Setting IP Address={ip} in device `{device.name}` on interface eth{iface_idx}.")

        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split(f"ip addr add {ip} dev eth{iface_idx}"),
            lab_name=device.lab.name
        )

        # Triggers the command.
        try:
            next(exec_output)
        except StopIteration:
            pass

    @staticmethod
    def _ip_addr_del(device: Machine, iface_idx: int, ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> None:
        logging.info(f"Deleting IP Address={ip} in device `{device.name}` on interface eth{iface_idx}.")

        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split(f"ip addr del {ip} dev eth{iface_idx}"),
            lab_name=device.lab.name
        )

        # Triggers the command.
        try:
            next(exec_output)
        except StopIteration:
            pass

    @staticmethod
    def _vendor_ip_add(device: Machine, config: VendorConfiguration,
                       iface_idx: int, ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> None:
        logging.info(f"Setting IP Address={ip} in device `{device.name}` on interface with idx={iface_idx}.")

        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split(config.command_set_iface_ip(iface_idx, ip)),
            lab_name=device.lab.name
        )

        # Triggers the command.
        try:
            next(exec_output)
        except StopIteration:
            pass

    @staticmethod
    def _vendor_ip_del(device: Machine, config: VendorConfiguration,
                       iface_idx: int, ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> None:
        logging.info(f"Removing IP Address={ip} in device `{device.name}` on interface with idx={iface_idx}.")

        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split(config.command_unset_iface_ip(iface_idx, ip)),
            lab_name=device.lab.name
        )

        # Triggers the command.
        try:
            next(exec_output)
        except StopIteration:
            pass

    @staticmethod
    def _ip_route_add(device: Machine,
                      net: ipaddress.IPv4Network | ipaddress.IPv6Network,
                      via_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                      via_iface_idx: int) -> None:
        logging.info(f"Setting IP Route={net} in device `{device.name}` on interface "
                     f"eth{via_iface_idx} via IP={via_ip}.")

        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split(f"ip route add {net} via {via_ip} dev eth{via_iface_idx}"),
            lab_name=device.lab.name
        )

        # Triggers the command.
        try:
            next(exec_output)
        except StopIteration:
            pass

    @staticmethod
    def _ip_route_del(device: Machine,
                      net: ipaddress.IPv4Network | ipaddress.IPv6Network,
                      via_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                      via_iface_idx: int) -> None:
        logging.info(f"Deleting IP Route={net} in device `{device.name}` on interface "
                     f"eth{via_iface_idx} via IP={via_ip}.")

        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split(f"ip route del {net} via {via_ip} dev eth{via_iface_idx}"),
            lab_name=device.lab.name
        )

        # Triggers the command.
        try:
            next(exec_output)
        except StopIteration:
            pass

    def _setup_dynamic_client(self, router, net_scenario: Lab,
                               picked_nets: dict[int, ipaddress.IPv4Network | ipaddress.IPv6Network],
                               assigned_ips: set) -> dict:
        border_name = router.machine_name
        client_name = f"{border_name}_dynamic_client"
        cd_name = f"{border_name}_dynamic_cd"

        logging.info(f"Creating dynamic client `{client_name}` for router `{border_name}` on CD `{cd_name}`...")

        cd_link = net_scenario.get_or_new_link(cd_name)

        if not net_scenario.has_machine(client_name):
            client_device = net_scenario.new_machine(client_name)
            client_device.add_meta('image', 'kathara/base')
            client_device.add_meta('ipv6', True)
        else:
            client_device = net_scenario.get_machine(client_name)

        if client_name not in cd_link.machines:
            net_scenario.connect_machine_to_link(client_name, cd_name)
            Kathara.get_instance().deploy_machine(client_device)
        else:
            Kathara.get_instance().deploy_machine(client_device)

        router_device = net_scenario.get_machine(border_name)
        if border_name not in cd_link.machines:
            logging.info(f"Connecting router `{border_name}` to CD `{cd_name}`...")
            n_ifaces_before = len(router_device.interfaces)
            Kathara.get_instance().connect_machine_to_link(router_device, cd_link)
            Kathara.get_instance().update_lab_from_api(net_scenario)
            n_ifaces_after = len(router_device.interfaces)
            logging.info(f"Router `{border_name}` interfaces before={n_ifaces_before} after={n_ifaces_after}, "
                         f"keys={sorted(router_device.interfaces.keys())}")
            if n_ifaces_after <= n_ifaces_before:
                logging.warning(f"Router `{border_name}` was NOT connected to CD `{cd_name}`!")
        else:
            logging.info(f"Router `{border_name}` already connected to CD `{cd_name}`.")

        router_iface_idx = max(router_device.interfaces.keys())
        logging.info(f"Using interface eth{router_iface_idx} for router `{border_name}`.")

        time.sleep(2)

        for cmd in [
            "sysctl -w net.ipv4.conf.all.rp_filter=0",
            "sysctl -w net.ipv4.conf.default.rp_filter=0",
            "sysctl -w net.ipv4.conf.eth0.rp_filter=0"
        ]:
            exec_out = Kathara.get_instance().exec(
                machine_name=client_name, command=shlex.split(cmd), lab_name=net_scenario.name
            )
            try:
                next(exec_out)
            except StopIteration:
                pass

        result = {
            'client_device': client_device,
            'client_name': client_name,
            'router_iface_idx': router_iface_idx,
        }

        for v, candidate_net in picked_nets.items():
            hosts = list(candidate_net.hosts())
            client_ip_iface = None
            router_ip_iface = None
            for h in hosts:
                iface = ipaddress.ip_interface(f"{h}/{candidate_net.prefixlen}")
                if iface not in assigned_ips:
                    if client_ip_iface is None:
                        client_ip_iface = iface
                        assigned_ips.add(iface)
                    elif router_ip_iface is None:
                        router_ip_iface = iface
                        assigned_ips.add(iface)
                    else:
                        break

            if client_ip_iface is None or router_ip_iface is None:
                raise RuntimeError(f"Not enough free IPs in {candidate_net}")

            default_net = ipaddress.IPv4Network("0.0.0.0/0") if v == 4 else ipaddress.IPv6Network("::/0")
            self._ip_addr_add(client_device, 0, client_ip_iface)
            self._ip_route_add(client_device, default_net, router_ip_iface.ip, 0)
            self._ip_addr_add(router_device, router_iface_idx, router_ip_iface)

            # Add host routes towards the client to avoid routing ambiguities.
            exec_output = Kathara.get_instance().exec(
                machine_name=router_device.name,
                command=shlex.split(f"ip route add {client_ip_iface.ip}/32 dev eth{router_iface_idx}"),
                lab_name=net_scenario.name
            )
            try:
                next(exec_output)
            except StopIteration:
                pass

            result[f'client_ip_v{v}'] = client_ip_iface
            result[f'router_ip_v{v}'] = router_ip_iface

        return result

    @staticmethod
    def _cleanup_dynamic_client(dc: dict, net_scenario: Lab) -> None:
        client_name = dc['client_name']
        border_name = client_name.replace('_dynamic_client', '')
        cd_name = f"{border_name}_dynamic_cd"

        try:
            client_device = dc['client_device']
            cd_link = net_scenario.get_link(cd_name)

            if cd_link:
                Kathara.get_instance().undeploy_link(cd_link)

            Kathara.get_instance().undeploy_machine(client_device)
        except Exception as e:
            logging.warning(f"Error during dynamic client cleanup for {client_name}: {e}")

    @staticmethod
    def _perform_spoofing_check(send_device: Machine, rcv_device: Machine,
                                candidate_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                                spoof_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                                dst_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, bool]:
        logging.info(f"Performing spoof check with IPs=(src={candidate_ip}, spoof={spoof_ip}, dst={dst_ip})...")

        v = candidate_ip.version

        exec_output_sniffer = Kathara.get_instance().exec(
            machine_name=rcv_device.name,
            command=shlex.split(f"/usr/bin/python3 /host_sniffer.py {dst_ip} {spoof_ip} {v}"),
            lab_name=send_device.lab.name
        )

        exec_output_spoof = Kathara.get_instance().exec(
            machine_name=send_device.name,
            command=shlex.split(f"/usr/bin/python3 /host_spoof_check.py {candidate_ip} {spoof_ip} {dst_ip} {v}"),
            lab_name=send_device.lab.name
        )

        # First, get the output from the spoof script
        result_spoof = None
        while result_spoof is None:
            time.sleep(2)
            try:
                (result_spoof, _) = next(exec_output_spoof)
            except StopIteration:
                pass

        spoof_passed = result_spoof.decode('utf-8').strip() == "1"
        logging.info(f"spoof test on candidate client passed={spoof_passed}")
        # Once exited, check what we captured on the sniffer
        result_sniff = None
        while result_sniff is None:
            time.sleep(2)
            try:
                (result_sniff, _) = next(exec_output_sniffer)
            except StopIteration:
                pass
        sniff_passed = result_sniff.decode('utf-8').strip() == "1"
        logging.info(f"sniff test on provider client passed={sniff_passed}")
        
        # For Debugging uncomment this 
        # if sniff_passed == False or spoof_passed == False:
            # Kathara.get_instance().connect_tty(machine_name=send_device.name, lab_name=send_device.lab.name)

        return (spoof_passed, sniff_passed)

    def name(self) -> str:
        return "spoofing"

    def display_name(self) -> str:
        return "Anti-Spoofing Check"
