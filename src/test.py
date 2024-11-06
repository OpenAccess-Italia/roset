import argparse
import logging
import os
import random

from rs4lk.actions.action_manager import ActionManager
from rs4lk.colored_logging import set_logging
from rs4lk.configuration.bgp_configuration import BgpConfiguration
from rs4lk.foundation.actions.action_result import WARNING
from rs4lk.foundation.exceptions import BgpRuntimeError, ConfigValidationError
from rs4lk.globals import DEFAULT_RIB
from rs4lk.model.topology import Topology
from rs4lk.mrt.table_dump import TableDump
from rs4lk.network_scenario.network_scenario_manager import NetworkScenarioManager
from rs4lk.parser.grammar_parser import GrammarParser


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config_path', type=str, required=True)
    parser.add_argument('--config_syntax', type=str, required=True)
    parser.add_argument('--rib_dump', type=str, required=False, default=DEFAULT_RIB)
    parser.add_argument('--exclude_checks', type=str, required=False, default="")
    parser.add_argument('--result-level', type=int, required=False, default=WARNING)

    return parser.parse_args()


def main(args):
    random.seed(3000)

    grammar_parser = GrammarParser()
    vendor_config = grammar_parser.parse(args.config_path, args.config_syntax)

    rib_dump_file = os.path.abspath(args.rib_dump)
    table_dump = TableDump(rib_dump_file)
    topology = Topology(vendor_config, table_dump)

    net_scenario_manager = NetworkScenarioManager()
    net_scenario = net_scenario_manager.build_from_topology(vendor_config.name, topology)

    bgp_config = BgpConfiguration(topology)
    bgp_config.apply_to_network_scenario(net_scenario)

    vendor_config.apply_to_network_scenario(net_scenario)

    logging.info("Deploying network scenario...")
    net_scenario_manager.start_candidate_device(net_scenario, vendor_config)
    net_scenario_manager.start_other_devices(net_scenario, vendor_config)
    logging.success("Network scenario deployed successfully.")

    all_passed = False
    try:
        action_manager = ActionManager(exclude=args.exclude_checks.split(','))
        results = action_manager.start(vendor_config, topology, net_scenario)
        all_passed = all([x.passed() for x in results])

        for result in results:
            result.print(level=args.result_level)
    except ConfigValidationError as e:
        logging.error(e)
        pass
    except BgpRuntimeError as e:
        logging.error(e)
        pass

    table_dump.close()

    net_scenario_manager.undeploy(net_scenario)

    # 0=Configuration is compliant, 1=Configuration is not compliant
    exit(int(all_passed))


if __name__ == "__main__":
    set_logging()

    main(parse_args())
