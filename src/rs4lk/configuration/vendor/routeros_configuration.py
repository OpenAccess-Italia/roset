import ipaddress
import logging
import re

from Kathara.model.Lab import Lab

from ...foundation.configuration.vendor_configuration import VendorConfiguration
from ...model.interface import Interface, VlanInterface


class RouterosConfiguration(VendorConfiguration):
    # Number of supported interfaces in vrnetlab RouterOS VM
    SUPPORTED_IFACES: int = 32

    CONFIG_FILE_NAME: str = "config.auto.rsc"
    CONFIG_FILE_PATH: str = f"/ftpboot/{CONFIG_FILE_NAME}"

    ROS_MGMT_ADDR: str = "172.31.255.30"
    CLI_CMD: str = ("sshpass -p VR-netlab9 ssh -q "
                    "-oStrictHostKeyChecking=no -oConnectTimeout=1 vrnetlab@" + ROS_MGMT_ADDR + " '{command}'")

    PREFIX_REGEX: re.Pattern = re.compile(r"dst-address=(.*)")

    def _remap_interfaces(self) -> None:
        # This is the mgmt interface
        self.iface_to_iface_idx["ether1"] = 0

        last_iface_idx = [1]
        for iface in self.interfaces.values():
            if not isinstance(iface, VlanInterface):
                self._remap_interface(iface, last_iface_idx)

        # Fill up missing interfaces
        for idx in range(last_iface_idx[0], self.SUPPORTED_IFACES + 1):
            name = self._build_iface_name('ether', idx)
            self.iface_to_iface_idx[name] = idx - 1

        for iface in self.interfaces.values():
            if isinstance(iface, VlanInterface):
                phy_idx = self.iface_to_iface_idx[iface.phy.name]
                self.iface_to_iface_idx[iface.name] = phy_idx

    def _remap_interface(self, iface: Interface, last_iface_idx: list[int]) -> None:
        if '-' not in iface.name:
            return

        last_iface_idx[0] += 1

        # vrnetlab names all the ports as "etherX", "ether1" is management.
        iface.rename(self._build_iface_name('ether', last_iface_idx[0]))

        self.iface_to_iface_idx[iface.name] = last_iface_idx[0] - 1

        logging.debug(f"Interface `{iface.original_name}` remapped into `{iface.name}`.")
    
    def get_image(self) -> str:
        return self.docker_image or 'vrnetlab/mikrotik_routeros:7.16.1'

    def apply_to_network_scenario(self, net_scenario: Lab, machine_name: str | None = None) -> None:
        candidate_name = machine_name or f"as{self.local_as}"
        candidate_router = net_scenario.get_machine(candidate_name)
        candidate_router.add_meta('privileged', True)
        candidate_router.add_meta('image', self.get_image())
        # Allocate slots for the interfaces
        candidate_router.add_meta('env', f"CLAB_INTFS={self.SUPPORTED_IFACES - 1}")

        all_lines = "\n".join(self.get_lines())
        candidate_router.create_file_from_string(all_lines, self.CONFIG_FILE_PATH)

    def get_lines(self) -> list[str]:
        iface_lines = []
        more_lines = False
        for line in self._lines:
            # Skip all the loopback and ether1 configurations (already applied by vrnetlab)
            if 'name=loopback' in line or 'interface=loopback' in line or 'interfaces=loopback' in line or \
                    'name=ether1' in line or 'interface=ether1' in line or 'interfaces=ether1' in line:
                more_lines = line.strip().endswith('\\')
                continue

            if more_lines:
                more_lines = line.strip().endswith('\\')
                continue

            iface_lines.append(line)

        all_lines = "".join(iface_lines)
        for iface_name, iface in self.interfaces.items():
            if '-' not in iface_name:
                continue

            all_lines = re.sub(
                rf"\b{iface.original_name}\b",
                iface.name,
                all_lines
            )

        skipping = False
        tmp_clean_lines = []
        for line in all_lines.split("\n"):
            # Clean disk configuration and switching configurations (not supported by vrnetlab)
            if '/disk' in line or '/interface ethernet switch' in line:
                skipping = True
                continue

            # We reached a new section, we can stop skipping
            if line.startswith('/') and skipping:
                skipping = False

            if skipping:
                continue

            tmp_clean_lines.append(line)

        clean_lines = []
        for num, line in enumerate(tmp_clean_lines):
            # Fix the "set name" line if it does not start with "/system identity"
            if 'set name' in line:
                curr_line = num - 1 if num > 0 else 0
                found_system = False
                while True:
                    # Beginning of section
                    if tmp_clean_lines[curr_line].startswith('/'):
                        if line.startswith('/system identity'):
                            # We found the system identity command
                            found_system = True
                            break
                        else:
                            # Another section was found, we just break
                            break

                    # Beginning of the file, exit
                    if curr_line == 0:
                        break

                    curr_line -= 1

                if not found_system:
                    clean_lines.append("/system identity")
                clean_lines.append(line)
            else:
                clean_lines.append(line)

        # Convert to terse configuration, so that the "import" command from ssh works
        terse_lines = []
        current_section = None
        continuation = False
        for line in clean_lines:
            if line.startswith('/'):
                current_section = line
                terse_lines.append(line)
                continue

            if not continuation:
                if line:
                    terse_lines.append(f"{current_section} {line}" if current_section else line)
            else:
                terse_lines.append(line)

            continuation = line.strip().endswith('\\')

        return terse_lines

    @staticmethod
    def _build_iface_name(iface_type: str, num: int) -> str:
        return f"{iface_type}{num}"

    # CommandsMixin
    def command_healthcheck(self) -> str:
        command = self.CLI_CMD.format(command="/system/health/print")
        logging.debug(f"[{__class__}] command_healthcheck: `{command}`")
        return command

    def command_list_file(self) -> str:
        command = self.CLI_CMD.format(command=f"/file/read file=\"{self.CONFIG_FILE_NAME}\" chunk-size=1")
        logging.debug(f"[{__class__}] command_list_file: `{command}`")
        return command

    def command_test_configuration(self) -> str:
        command = self.CLI_CMD.format(command=f"import verbose=progress {self.CONFIG_FILE_NAME} dry-run")
        logging.debug(f"[{__class__}] command_test_configuration: `{command}`")
        return command

    def command_get_neighbour_bgp(self, neighbour_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        command = self.CLI_CMD.format(
            command=f"/routing/bgp/session/print without-paging proplist=\"uptime\" terse "
                    f"where remote.address=\"{str(neighbour_ip)}\""
        )
        logging.debug(f"[{__class__}] command_get_neighbour_bgp: `{command}`")
        return command

    def command_get_neighbour_bgp_networks(self, neighbour_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        ip_str = "IP" if neighbour_ip.version == 4 else "IP6"

        command = self.CLI_CMD.format(
            command=f"/routing/route/print without-paging proplist=\"dst-address\" terse "
                    f"where belongs-to=\"bgp-{ip_str}-{str(neighbour_ip)}\""
        )
        logging.debug(f"[{__class__}] command_get_neighbour_bgp_networks: `{command}`")
        return command

    def command_set_iface_ip(self, num: int, ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> str:
        iface_name = RouterosConfiguration._build_iface_name("ether", num + 1)
        ip_str = "ip" if ip.version == 4 else "ipv6"
        advertise = 'advertise="no"' if ip.version == 6 else ""

        command = self.CLI_CMD.format(
            command=f"/{ip_str}/address/add address=\"{str(ip)}\" {advertise} interface=\"{iface_name}\""
        )
        logging.debug(f"[{__class__}] command_set_iface_ip: `{command}`")
        return command

    def command_unset_iface_ip(self, num: int, ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> str:
        iface_name = RouterosConfiguration._build_iface_name("ether", num + 1)
        ip_str = "ip" if ip.version == 4 else "ipv6"

        command = self.CLI_CMD.format(
            command=f"/{ip_str}/address/remove numbers=[find address=\"{str(ip)}\" interface=\"{iface_name}\"]"
        )
        logging.debug(f"[{__class__}] command_unset_iface_ip: `{command}`")
        return command

    # FormatParserMixin
    def check_health(self, result: str) -> bool:
        return result.strip() != ""

    def check_file_existence(self, result: str) -> bool:
        return "input does not match any value of file" not in result.lower()

    def check_configuration_validity(self, result: str) -> bool:
        return "no syntax errors" in result.lower()

    def check_bgp_state(self, result: str) -> bool:
        return 'uptime=' in result

    def parse_bgp_routes(self, result: str) -> set:
        bgp_routes = set()
        for line in result.split("\n"):
            if 'dst-address=' not in line:
                continue

            matches = self.PREFIX_REGEX.search(line)
            if matches:
                bgp_routes.add(ipaddress.ip_network(matches.group(1).strip()))

        return bgp_routes
