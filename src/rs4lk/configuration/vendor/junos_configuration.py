import ipaddress
import json
import logging
import re

from Kathara.model.Lab import Lab

from ...foundation.configuration.vendor_configuration import VendorConfiguration
from ...model.interface import Interface, VlanInterface


class JunosConfiguration(VendorConfiguration):
    # Number of supported interfaces in vrnetlab VMX VM
    SUPPORTED_IFACES: int = 50

    CLI_CMD: str = ("sshpass -p VR-netlab9 ssh -q "
                    "-oStrictHostKeyChecking=no -oConnectTimeout=1 vrnetlab@localhost \"{command}\"")

    def _remap_interfaces(self) -> None:
        # Iface 0 is the mgmt interface
        last_iface_idx = [0]
        for iface in self.interfaces.values():
            if not isinstance(iface, VlanInterface):
                self._remap_interface(iface, last_iface_idx)

        # Fill up missing interfaces
        for idx in range(last_iface_idx[0] + 1, self.SUPPORTED_IFACES):
            name = self._build_iface_name('ge', 0, 0, idx, 0)
            self.iface_to_iface_idx[name] = idx

        for iface in self.interfaces.values():
            if isinstance(iface, VlanInterface):
                phy_idx = self.iface_to_iface_idx[iface.phy.name]
                iface.rename(self._build_iface_name('ge', 0, 0, phy_idx, iface.vlan))
                self.iface_to_iface_idx[iface.name] = phy_idx

    def _remap_interface(self, iface: Interface, last_iface_idx: list[int]) -> None:
        if '-' not in iface.name:
            return

        last_iface_idx[0] += 1
        unit = 0

        # Put it as 'ge', in slot 0 and port 0
        iface.rename(self._build_iface_name('ge', 0, 0, last_iface_idx[0], unit))

        self.iface_to_iface_idx[iface.name] = last_iface_idx[0]

        logging.debug(f"Interface `{iface.original_name}` remapped into `{iface.name}`.")

    def get_image(self) -> str:
        return 'vrnetlab/vr-vmx:18.2R1.9'

    def apply_to_network_scenario(self, net_scenario: Lab) -> None:
        net_scenario.add_option('privileged_machines', True)

        candidate_name = f"as{self.local_as}"
        candidate_router = net_scenario.get_machine(candidate_name)
        candidate_router.add_meta('image', self.get_image())
        # Allocate slots for the interfaces
        candidate_router.add_meta('env', f"CLAB_INTFS={self.SUPPORTED_IFACES - 1}")

        all_lines = "\n".join(self.get_lines())
        candidate_router.create_file_from_string(all_lines, self.CONFIG_FILE_PATH)

    def get_lines(self) -> list[str]:
        all_lines = "".join(self._lines)
        for iface_name, iface in self.interfaces.items():
            if '-' not in iface_name:
                continue

            if iface.original_name is not None:
                v_iface_type, v_slot, v_port, v_pic, v_unit = self._parse_iface_format(
                    iface.original_name
                )
                if v_unit is None:
                    v_unit = 0
                iface_type, slot, port, pic, unit = self._parse_iface_format(
                    iface.name
                )
                if unit is None:
                    unit = 0

                name_to_search = self._build_iface_name(v_iface_type, v_slot, v_port, v_pic, None)
                name_to_search_unit = f"{name_to_search} unit {v_unit}"

                name_to_replace = self._build_iface_name(iface_type, slot, port, pic, None)
                name_to_replace_unit = f"{name_to_replace} unit {unit}"

                all_lines = re.sub(
                    rf'\b{name_to_search_unit}\b',
                    name_to_replace_unit,
                    all_lines
                )
                all_lines = re.sub(
                    rf'\b{name_to_search}\b',
                    name_to_replace,
                    all_lines
                )

        clean_lines = []
        for line in all_lines.split("\n"):
            # Clean system setup lines (these are handled by the vrnetlab)
            if 'set version' in line or 'set system' in line or 'set chassis' in line:
                continue

            # Skip fxp0 configuration (it is done by vrnetlab)
            if 'set interfaces' in line and 'fxp0' in line:
                continue

            # Skip lines setting speed
            if 'set interface' in line and 'gigether-options speed' in line:
                continue

            # Skip SNMP
            if 'set snmp' in line:
                continue

            # Clean the BGP add path lines (not supported in VMX18)
            if 'set protocols bgp' in line and 'add-path' in line:
                if 'neighbor' in line:
                    line = line.replace(' add-path receive', '')
                else:
                    continue

            clean_lines.append(line)

        clean_lines = self._clean_filters_on_loopback(clean_lines)

        return clean_lines

    @staticmethod
    def _clean_filters_on_loopback(all_lines: list[str]) -> list[str]:
        filter_line_idx = -1

        for idx, line in enumerate(all_lines):
            if 'set interfaces lo0' in line and 'filter input':
                filter_line_idx = idx
                break

        if filter_line_idx != -1:
            all_lines.pop(filter_line_idx)

        return all_lines

    @staticmethod
    def _parse_iface_format(x) -> (str, int, int, int, int | None):
        (iface_type, iface_parts) = x.split('-')
        (slot, port, pic) = iface_parts.split('/')

        unit = None
        if '.' in pic:
            (pic, unit) = pic.split('.')

        return iface_type, int(slot), int(port), int(pic), int(unit) if unit else None

    @staticmethod
    def _build_iface_name(speed: str, slot: int, port: int, pic: int, unit: int | None, compact: bool = True) -> str:
        values = [str(slot), str(port), str(pic)]
        name = f"{speed}-" + "/".join(values)

        if unit is not None:
            name += (".%d" if compact else " unit %d") % unit

        return name

    # CommandsMixin
    def command_healthcheck(self) -> str:
        command = self.CLI_CMD.format(command="show system uptime")
        logging.debug(f"[{__class__}] command_healthcheck: `{command}`")
        return command

    def command_list_file(self) -> str:
        command = self.CLI_CMD.format(command="file list startup-config.cfg")
        logging.debug(f"[{__class__}] command_list_file: `{command}`")
        return command

    def command_test_configuration(self) -> str:
        command = self.CLI_CMD.format(command="configure; commit check; exit")
        logging.debug(f"[{__class__}] command_test_configuration: `{command}`")
        return command

    def command_get_neighbour_bgp(self, neighbour_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        command = self.CLI_CMD.format(command=f"show bgp neighbor {str(neighbour_ip)} | display json")
        logging.debug(f"[{__class__}] command_get_neighbour_bgp: `{command}`")
        return command

    def command_get_neighbour_bgp_networks(self, neighbour_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        command = self.CLI_CMD.format(command=f"show route receive-protocol bgp {str(neighbour_ip)} all | display json")
        logging.debug(f"[{__class__}] command_get_neighbour_bgp_networks: `{command}`")
        return command

    def command_set_iface_ip(self, num: int, ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> str:
        unit_name = JunosConfiguration._build_iface_name("ge", 0, 0, num, 0)
        inet_str = "inet" if ip.version == 4 else "inet6"

        command = self.CLI_CMD.format(
            command=f"configure; set interfaces {unit_name} family {inet_str} address {str(ip)}; commit; exit;"
        )
        logging.debug(f"[{__class__}] command_set_iface_ip: `{command}`")
        return command

    def command_unset_iface_ip(self, num: int, ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> str:
        unit_name = JunosConfiguration._build_iface_name("ge", 0, 0, num, 0)
        inet_str = "inet" if ip.version == 4 else "inet6"

        command = self.CLI_CMD.format(
            command=f"configure; delete interfaces {unit_name} family {inet_str} address {str(ip)}; commit; exit;"
        )
        logging.debug(f"[{__class__}] command_unset_iface_ip: `{command}`")
        return command

    # FormatParserMixin
    def check_health(self, result: str) -> bool:
        return result.strip() != ""

    def check_file_existence(self, result: str) -> bool:
        return "no such file or directory" not in result.lower()

    def check_configuration_validity(self, result: str) -> bool:
        return "configuration check succeeds" in result.lower()

    def check_bgp_state(self, result: str) -> bool:
        output = json.loads(result)
        state = output["bgp-information"][0]["bgp-peer"][0]["peer-state"][0]["data"]
        return state == "Established"

    def parse_bgp_routes(self, result: str) -> set:
        output = json.loads(result)

        bgp_routes = set()
        for route_table in output['route-information'][0]['route-table']:
            if 'rt' in route_table:
                for route_entry in route_table['rt']:
                    bgp_routes.add(ipaddress.ip_network(route_entry['rt-destination'][0]['data']))

        return bgp_routes
