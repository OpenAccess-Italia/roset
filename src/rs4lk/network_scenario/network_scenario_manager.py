import logging
import shlex
import time

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.model.Machine import Machine

from ..foundation.configuration.vendor_configuration import VendorConfiguration
from ..foundation.exceptions import NetworkScenarioError
from ..model.topology import BgpRouter, Node, Topology, Client


class NetworkScenarioManager:
    def build_from_topology(self, name: str, topology: Topology) -> Lab:
        logging.info("Creating Kathara network scenario from AS Topology...")

        if not topology:
            raise NetworkScenarioError("Cannot create network scenario")

        net_scenario = Lab(name)

        for as_num, node in topology.all():
            device = self._build_device(net_scenario, node)

            # Do not configure interfaces on candidate
            if isinstance(node, BgpRouter) and node.candidate:
                continue

            vlans = set()
            for iface_idx, neighbours in node.neighbours.items():
                with device.lab.fs.open(f"{device.name}.startup", 'a+') as startup:
                    for neighbour in neighbours.values():
                        for v_ips in neighbour.get_local_ips().values():
                            for (vlan, ip, _) in v_ips:
                                iface_name = f"eth{iface_idx}" if vlan is None else f"eth{iface_idx}.{vlan}"

                                if vlan is not None and vlan not in vlans:
                                    phy = f"eth{iface_idx}"
                                    startup.write(f"ip link add link {phy} name {iface_name} type vlan id {vlan}\n")
                                    startup.write(f"ip link set dev {iface_name} up\n")
                                    vlans.add(vlan)

                                startup.write(f"ip addr add {ip} dev {iface_name}\n")

        return net_scenario

    def _build_device(self, net_scenario: Lab, node: Node) -> Machine:
        device_name = node.name

        if not net_scenario.has_machine(node.name):
            device = net_scenario.new_machine(device_name)
            logging.info(f"Device `{device_name}` created.")

            if isinstance(node, BgpRouter):
                device.add_meta('image', 'kathara/frr')
            elif isinstance(node, Client):
                device.add_meta('image', 'kathara/base')

            # Do not configure IPv6 on candidate
            if isinstance(node, BgpRouter) and node.candidate:
                device.add_meta('ipv6', False)
            else:
                device.add_meta('ipv6', True)

            for iface_idx, neighbours in node.neighbours.items():
                cd = node.get_cd_by_iface_idx(iface_idx)
                net_scenario.connect_machine_to_link(device_name, cd, machine_iface_number=iface_idx)

                logging.info(f"Device `{device_name}` connected " +
                             f"on collision domain `{cd}` with "
                             f"interface idx={iface_idx}.")

                for neighbour in neighbours.values():
                    logging.info(f"Connecting `{device_name}` with neighbour `{neighbour.neighbour.name}` "
                                 f"on collision domain `{cd}` with "
                                 f"interface idx={iface_idx}.")

                    self._build_device(net_scenario, neighbour.neighbour)

            return device
        else:
            return net_scenario.get_machine(device_name)

    @staticmethod
    def start_candidate_device(net_scenario: Lab, vendor_config: VendorConfiguration) -> None:
        candidate_device = net_scenario.machines[f"as{vendor_config.local_as}"]

        logging.info(f"Starting candidate device `{candidate_device.name}`...")
        Kathara.get_instance().deploy_machine(candidate_device)
        
        if hasattr(vendor_config, 'command_start_daemon'):
            logging.info(f"Starting vendor daemon for `{candidate_device.name}`...")
            exec_output = Kathara.get_instance().exec(
                machine_name=candidate_device.name,
                command=shlex.split(vendor_config.command_start_daemon()),
                lab_name=net_scenario.name
            )
            try:
                while True:
                    try:
                        stdout, stderr = next(exec_output)
                        stdout = stdout.decode('utf-8') if stdout else ""
                        stderr = stderr.decode('utf-8') if stderr else ""
                        logging.debug(f"[DAEMON START] stdout='{stdout}', stderr='{stderr}'")
                    except StopIteration:
                        break
            except StopIteration:
                pass
        
        logging.info(f"Waiting candidate device `{candidate_device.name}` startup...")

        is_running = False
        attempts = 0
        max_attempts = 60
        start_time = time.time()
        while not is_running:
            if attempts >= max_attempts:
                raise NetworkScenarioError(f"Candidate device `{candidate_device.name}` failed to start after {max_attempts} attempts ({(time.time() - start_time):.0f}s)")
            
            exec_output = Kathara.get_instance().exec(
                machine_name=candidate_device.name,
                command=shlex.split(vendor_config.command_healthcheck()),
                lab_name=net_scenario.name
            )

            try:
                (stdout, stderr) = next(exec_output)
                stdout = stdout.decode('utf-8') if stdout else ""
                stderr = stderr.decode('utf-8') if stderr else ""
                attempts += 1
                logging.debug(f"[HEALTHCHECK] attempt {attempts}: stdout='{stdout}', stderr='{stderr}'")
                is_running = vendor_config.check_health(stdout)
            except StopIteration:
                attempts += 1
                logging.debug(f"[HEALTHCHECK] attempt {attempts}: no output, sleeping...")
                time.sleep(5)
                pass
        
        if hasattr(vendor_config, 'get_post_start_commands'):
            post_commands = vendor_config.get_post_start_commands()
            for cmd in post_commands:
                logging.info(f"Executing post-start command: {cmd}")
                exec_output = Kathara.get_instance().exec(
                    machine_name=candidate_device.name,
                    command=shlex.split(cmd),
                    lab_name=net_scenario.name
                )
                try:
                    while True:
                        try:
                            stdout, stderr = next(exec_output)
                            stdout = stdout.decode('utf-8') if stdout else ""
                            stderr = stderr.decode('utf-8') if stderr else ""
                            logging.debug(f"[POST-START] stdout='{stdout}', stderr='{stderr}'")
                        except StopIteration:
                            break
                except StopIteration:
                    pass

    def start_other_devices(self, net_scenario: Lab, vendor_config: VendorConfiguration) -> None:
        logging.info("Starting all other devices...")

        all_except_candidate = {x for x in net_scenario.machines.keys() if x != f"as{vendor_config.local_as}"}
        Kathara.get_instance().deploy_lab(net_scenario, selected_machines=all_except_candidate)

        not_healthy_routers = [x for x in all_except_candidate if "_client" not in x]
        n_routers = len(not_healthy_routers)
        n_healthy = 0
        while n_healthy != n_routers:
            for i, device_name in enumerate(not_healthy_routers):
                logging.debug(f"Checking health of device `{device_name}`...")

                device = net_scenario.get_machine(device_name)

                is_healthy = self._check_router_health(device)
                if not is_healthy:
                    logging.warning(f"Device `{device_name}` did not start correctly! Restarting...")
                    Kathara.get_instance().undeploy_machine(device)
                    Kathara.get_instance().deploy_machine(device)
                else:
                    n_healthy += 1
                    not_healthy_routers.pop(i)

    @staticmethod
    def _check_router_health(device: Machine) -> bool:
        # Print bgpd.conf file to compare it
        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split("cat /etc/frr/bgpd.conf"),
            lab_name=device.lab.name
        )
        config_out = ""
        config_err = ""
        try:
            while True:
                (stdout, stderr) = next(exec_output)
                stdout = stdout.decode('utf-8') if stdout else ""
                stderr = stderr.decode('utf-8') if stderr else ""

                if stdout:
                    config_out += stdout
                if stderr:
                    config_err += stderr
        except StopIteration:
            pass

        # /etc/frr/bgpd.conf file is not copied
        if config_out == "" and "No such file or directory" in config_err:
            return False
        # /etc/frr/bgpd.conf file is copied but not correctly
        with device.fs.open('/etc/frr/bgpd.conf', 'r') as bgpd:
            static_config = bgpd.readlines()
        static_config = list(filter(lambda x: x != '', [x.strip() for x in static_config]))
        runtime_config = list(filter(lambda x: x != '', [x.strip() for x in config_out.split("\n")]))
        if runtime_config != static_config:
            return False

        # If configuration files exist and is correct, check if BGP is running
        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split("vtysh -c 'show bgp summary'"),
            lab_name=device.lab.name
        )
        vtysh_out = ""
        vtysh_err = ""
        try:
            while True:
                (stdout, stderr) = next(exec_output)
                stdout = stdout.decode('utf-8') if stdout else ""
                stderr = stderr.decode('utf-8') if stderr else ""

                if stdout:
                    vtysh_out += stdout
                if stderr:
                    vtysh_err += stderr
        except StopIteration:
            pass

        # Something is wrong with /etc/frr/daemons file
        if vtysh_out == "" and "bgpd is not running" in vtysh_err:
            return False
        # Something is wrong with BGP instance
        if "% BGP instance not found" in vtysh_out:
            return False

        return True

    @staticmethod
    def undeploy(net_scenario: Lab) -> None:
        logging.info("Undeploying network scenario...")
        Kathara.get_instance().undeploy_lab(net_scenario.hash)
