import ipaddress
import logging
import os
import re

from Kathara.model.Lab import Lab

from ...foundation.configuration.vendor_configuration import VendorConfiguration
from ...model.interface import Interface, VlanInterface


class FrrConfiguration(VendorConfiguration):
    CONFIG_FILE_PATH: str = "/etc/frr/frr.conf"
    VTYSH_COMMAND: str = "vtysh -c \"{command}\""
    PREFIX_REGEX: re.Pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+/\d+)")

    def get_image(self) -> str:
        return self.docker_image or 'kathara/frr:9'

    def _remap_interfaces(self) -> None:
        idx = 0
        for iface in self.interfaces.values():
            if not isinstance(iface, VlanInterface):
                self.iface_to_iface_idx[iface.name] = idx
                idx += 1

        for iface in self.interfaces.values():
            if isinstance(iface, VlanInterface):
                phy_idx = self.iface_to_iface_idx[iface.phy.name]
                self.iface_to_iface_idx[iface.name] = phy_idx

    def apply_to_network_scenario(self, net_scenario: Lab, machine_name: str | None = None,
                              startup_script_path: str | None = None) -> None:
        candidate_name = machine_name or f"as{self.local_as}"
        candidate_router = net_scenario.get_machine(candidate_name)
        candidate_router.add_meta('privileged', True)
        candidate_router.add_meta('image', self.get_image())

        env_ifaces = []
        for iface_name, iface_idx in self.iface_to_iface_idx.items():
            if "." in iface_name:
                continue
            env_ifaces.append(f"eth{iface_idx}")

        candidate_router.add_meta('env', "FRR_PIDFILE=/var/run/frr/frr.pid")

        all_lines = "\n".join(self.get_lines())
        candidate_router.create_file_from_string(all_lines, self.CONFIG_FILE_PATH)
        candidate_router.create_file_from_string(
            "bgpd=yes\nzebra=yes\n",
            "/etc/frr/daemons"
        )
        
        startup_commands = [
            "/usr/lib/frr/frrinit.sh start",
            "sleep 2",
            "while ! pgrep bgpd > /dev/null; do sleep 1; done",
            "echo 'FRR started successfully'",
        ]
        candidate_router.create_file_from_string(
            "#!/bin/bash\n" + "\n".join(startup_commands) + "\n",
            "/etc/supervisor/startup.sh"
        )
        candidate_router.add_meta('post_start', '/bin/bash /etc/supervisor/startup.sh')
        
        self._apply_firewall_config(candidate_router, startup_script_path)
    
    def get_post_start_commands(self) -> list[str]:
        commands = []
        
        commands.append('/bin/bash /etc/supervisor/startup_script.sh')
        
        return commands

    # Unused, but kept for consistency with the other configurations.
    def get_lines(self) -> list[str]:
        cleaned = []
        skip_until_next_bang = False
        
        for line in self._lines:
            stripped = line.strip()
            
            if not stripped:
                continue
            
            if stripped in ('Building configuration...', 'Current configuration:'):
                skip_until_next_bang = True
                continue
            
            if skip_until_next_bang:
                if stripped == '!':
                    skip_until_next_bang = False
                continue
            
            if stripped.startswith('frr version') or stripped.startswith('frr defaults'):
                continue
            
            if stripped in ('end', '!'):
                continue
                
            cleaned.append(stripped)
        
        return cleaned

    def _build_iface_name(self, iface_type: str, num: int) -> str:
        return f"{iface_type}{num}"

    def command_healthcheck(self) -> str:
        command = "pgrep bgpd"
        logging.debug(f"[{__class__}] command_healthcheck: `{command}`")
        return command

    def command_start_daemon(self) -> str:
        command = "/usr/lib/frr/frrinit.sh start"
        logging.debug(f"[{__class__}] command_start_daemon: `{command}`")
        return command

    def command_list_file(self) -> str:
        command = f"ls {self.CONFIG_FILE_PATH}"
        logging.debug(f"[{__class__}] command_list_file: `{command}`")
        return command

    def command_test_configuration(self) -> str:
        command = self.VTYSH_COMMAND.format(command="show running-config")
        logging.debug(f"[{__class__}] command_test_configuration: `{command}`")
        return command

    def command_get_neighbour_bgp(self, neighbour_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        command = self.VTYSH_COMMAND.format(
            command=f"show ip bgp neighbors {str(neighbour_ip)}"
        )
        logging.info(f"[{__class__}] command_get_neighbour_bgp: `{command}`")
        return command

    def command_get_neighbour_bgp_networks(self, neighbour_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        command = self.VTYSH_COMMAND.format(
            command=f"show ip bgp neighbors {str(neighbour_ip)} routes"
        )
        logging.debug(f"[{__class__}] command_get_neighbour_bgp_networks: `{command}`")
        return command

    def command_set_iface_ip(self, num: int, ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> str:
        iface_name = self._build_iface_name("eth", num)
        ip_str = "ip" if ip.version == 4 else "ipv6"

        command = self.VTYSH_COMMAND.format(
            command=f"configure terminal\ninterface {iface_name}\n {ip_str} address {str(ip)}\nend\nwrite memory"
        )
        logging.debug(f"[{__class__}] command_set_iface_ip: `{command}`")
        return command

    def command_unset_iface_ip(self, num: int, ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> str:
        iface_name = self._build_iface_name("eth", num)
        ip_str = "ip" if ip.version == 4 else "ipv6"

        command = self.VTYSH_COMMAND.format(
            command=f"configure terminal\ninterface {iface_name}\n no {ip_str} address {str(ip)}\nend\nwrite memory"
        )
        logging.debug(f"[{__class__}] command_unset_iface_ip: `{command}`")
        return command

    def check_health(self, result: str) -> bool:
        return result.strip() != ""

    def check_file_existence(self, result: str) -> bool:
        return "no such file or directory" not in result.lower()

    def check_configuration_validity(self, result: str) -> bool:
        return result.strip() != ""

    def check_bgp_state(self, result: str) -> bool:
        for line in result.split("\n"):
            if 'BGP state' not in line and 'State:' not in line:
                continue
            if "Established" in line:
                return True
        return False

    def parse_bgp_routes(self, result: str) -> set:
        bgp_routes = set()
        for line in result.split("\n"):
            matches = self.PREFIX_REGEX.search(line)
            if matches:
                try:
                    bgp_routes.add(ipaddress.ip_network(matches.group(1)))
                except ValueError:
                    continue
        return bgp_routes

    def _apply_firewall_config(self, candidate_router, startup_script_path: str | None = None) -> None:
        if not startup_script_path:
            logging.debug("No startup script specified, skipping")
            return
        
        if not os.path.exists(startup_script_path):
            logging.debug(f"Startup script not found: {startup_script_path}")
            return
        
        logging.info(f"Applying startup script from `{startup_script_path}`...")
        
        with open(startup_script_path, 'r') as f:
            lines = f.read().strip().split('\n')
        
        startup_content = []
        startup_content.append("#!/bin/bash")
        startup_content.append("")
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            startup_content.append(line)
        
        candidate_router.create_file_from_string(
            "\n".join(startup_content) + "\n",
            "/etc/supervisor/startup_script.sh"
        )
        
        candidate_router.add_meta('post_start', '/bin/bash /etc/supervisor/startup_script.sh')
