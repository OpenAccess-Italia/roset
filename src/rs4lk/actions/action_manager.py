import json
import logging
import shlex
import time

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.model.Machine import Machine

from .antispoofing_action import AntiSpoofingAction
from .global_information_action import GlobalInformationAction
from .route_leak_action import RouteLeakAction
from ..foundation.actions.action import Action
from ..foundation.actions.action_result import ActionResult
from ..foundation.configuration.vendor_configuration import VendorConfiguration
from ..foundation.exceptions import BgpRuntimeError, ConfigValidationError
from ..model.topology import Topology, Client, BgpRouter
from ..mrt.table_dump import TableDump

CONVERGENCE_ATTEMPTS = 100


class ActionManager:
    __slots__ = ['_actions']

    DEFAULT_ACTIONS: list[Action] = [GlobalInformationAction(), AntiSpoofingAction(), RouteLeakAction()]

    def __init__(self, exclude: list[str] | None = None):
        if exclude is None:
            self._actions: list[Action] = self.DEFAULT_ACTIONS
        else:
            self._actions: list[Action] = list(filter(lambda x: x.name() not in exclude, self.DEFAULT_ACTIONS))

    def start(
            self, config: VendorConfiguration, topology: Topology, table_dump: TableDump, net_scenario: Lab
    ) -> list[ActionResult]:
        self._check_configuration_validity(config, net_scenario)

        converged = self._wait_convergence(topology, net_scenario)
        if not converged:
            raise BgpRuntimeError("BGP did not converge")

        results = []

        logging.info("Starting MANRS actions check...")
        for action in self._actions:
            logging.info(f"Starting `{action.display_name()}` verification...")
            action_result = action.verify(config, table_dump, topology, net_scenario)
            results.append(action_result)

        return results

    @staticmethod
    def _check_configuration_validity(config: VendorConfiguration, net_scenario: Lab) -> None:
        candidate_device = net_scenario.get_machine(f"as{config.local_as}")

        # Check until the file is copied
        found = False
        while not found:
            exec_output = Kathara.get_instance().exec(
                machine_name=candidate_device.name,
                command=shlex.split(config.command_list_file()),
                lab_name=net_scenario.name
            )

            output = ""
            while True:
                try:
                    (stdout, stderr) = next(exec_output)
                    output += stdout.decode('utf-8')
                except StopIteration:
                    break

            found = config.check_file_existence(output)

        # Now check if there are any errors in the configuration
        exec_output = Kathara.get_instance().exec(
            machine_name=candidate_device.name,
            command=shlex.split(config.command_test_configuration()),
            lab_name=net_scenario.name
        )

        output = ""
        while True:
            try:
                (stdout, stderr) = next(exec_output)
                output += stdout.decode('utf-8')
            except StopIteration:
                break

        if not config.check_configuration_validity(output):
            raise ConfigValidationError(output)

    def _wait_convergence(self, topology: Topology, net_scenario: Lab) -> bool:
        logging.info("Checking routers convergence...")

        selected_nodes = dict(
            map(
                lambda x: (x[1].name, x[1]),
                filter(lambda x: type(x[1]) != Client and not x[1].candidate, topology.all())
            )
        )
        selected_devices = set(x for x in net_scenario.machines.values() if x.name in selected_nodes)

        attempts = 0
        counter = 0
        while not counter >= 3:
            time.sleep(3)

            if attempts >= CONVERGENCE_ATTEMPTS:
                logging.error(f"BGP is not converging: {CONVERGENCE_ATTEMPTS} attempts. Aborting.")
                return False

            converged_routers = self._bgp_established(selected_nodes, selected_devices)
            if all(converged_routers):
                counter += 1
            else:
                counter = 0
                attempts += 1

            converged_routers_count = sum([1 for x in converged_routers if x])
            logging.info(f"[ATTEMPT {attempts}] {converged_routers_count}/{len(converged_routers)} routers converged!")

        logging.info("Routers converged!")

        return True

    def _bgp_established(self, selected_nodes: dict[str, BgpRouter], selected_devices: set[Machine]) -> list:
        summaries = self._get_routers_summary(selected_devices)

        converged_routers = []

        for device_name, summary in summaries.items():
            has_ipv4 = False
            flag_ipv4 = True
            routes_ipv4 = True
            has_ipv6 = False
            flag_ipv6 = True
            routes_ipv6 = True

            if not summary:
                converged_routers.append(False)
                continue

            if 'ipv4Unicast' in summary:
                has_ipv4 = True
                flag_ipv4 = summary['ipv4Unicast']['failedPeers'] == 0

                # Check if the providers received the routes
                if selected_nodes[device_name].is_provider():
                    routes_ipv4 = all([x['pfxRcd'] > 0 for x in summary['ipv4Unicast']['peers'].values()])
                else:
                    routes_ipv4 = True

            if 'ipv6Unicast' in summary:
                has_ipv6 = True
                flag_ipv6 = summary['ipv6Unicast']['failedPeers'] == 0

                # Check if the providers received the routes
                if selected_nodes[device_name].is_provider():
                    routes_ipv6 = all([x['pfxRcd'] > 0 for x in summary['ipv6Unicast']['peers'].values()])
                else:
                    routes_ipv6 = True

            logging.debug(f"device={device_name}, "
                          f"ipv4_ready={flag_ipv4}, routes_ipv4={routes_ipv4}, "
                          f"ipv6_ready={flag_ipv6}, routes_ipv6={routes_ipv6}")

            inc = flag_ipv4 and routes_ipv4 if has_ipv4 else True
            inc = flag_ipv6 and routes_ipv6 and inc if has_ipv6 else inc
            converged_routers.append(inc)

        return converged_routers

    @staticmethod
    def _get_routers_summary(selected_devices: set[Machine]) -> dict:
        summaries = {}

        for device in selected_devices:
            logging.debug(f"Querying router `{device.name}`...")

            exec_output = Kathara.get_instance().exec(
                machine_name=device.name,
                command=shlex.split("vtysh -c 'show bgp summary json'"),
                lab_name=device.lab.name
            )

            bgp_summary = ""
            try:
                while True:
                    (stdout, _) = next(exec_output)
                    stdout = stdout.decode('utf-8') if stdout else ""

                    if stdout:
                        bgp_summary += stdout
            except StopIteration:
                pass

            try:
                bgp_summary = json.loads(bgp_summary)
            except ValueError:
                bgp_summary = None
                logging.error(f"Unable to parse BGP JSON of device `{device.name}`.")

            summaries[device.name] = bgp_summary

        return summaries
