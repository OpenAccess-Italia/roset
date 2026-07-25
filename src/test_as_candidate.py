#!/usr/bin/env python3
import argparse
import logging
import os
import random
import sys

from rs4lk.actions.action_manager import ActionManager
from rs4lk.colored_logging import set_logging
from rs4lk.configuration.bgp_configuration import BgpConfiguration
from rs4lk.foundation.actions.action_result import WARNING
from rs4lk.foundation.exceptions import BgpRuntimeError, ConfigValidationError
from rs4lk.globals import DEFAULT_RIB
from rs4lk.model.topology import BgpRouter, Client, Topology
from rs4lk.mrt.table_dump import TableDump
from rs4lk.network_scenario.network_scenario_manager import NetworkScenarioManager
from rs4lk.parser import AsCandidateParser
from rs4lk.utils import Timer
from rs4lk.webhooks.ripe_db import RipeDb


def parse_args():
    parser = argparse.ArgumentParser(description='Test AS Candidate with multiple routers')
    parser.add_argument('--as_config', '-c', type=str, required=True,
                        help='Path to the AS candidate JSON configuration file')
    parser.add_argument('--rib_dump', type=str, required=False, default=None,
                        help='Path to the MRT RIB dump file (default: from JSON config or resources/rib_latest.db)')
    parser.add_argument('--relationships', type=str, required=False, default=None,
                        help='Path to local relationships JSON file')
    parser.add_argument('--exclude_checks', type=str, required=False, default="",
                        help='Comma-separated list of checks to exclude')
    parser.add_argument('--result-level', type=int, required=False, default=WARNING,
                        help='Minimum result level')
    parser.add_argument('--name', type=str, required=False, default=None,
                        help='Network scenario name (default: as_local_as)')
    parser.add_argument('--debug', action='store_true', 
                        help='Enable debug messages'
    )
    parser.add_argument('--file', type=str, required=False, default=None,
                        help='Save the final results to the specified file'
    )
    return parser.parse_args()


def main(args):
    random.seed(3000)
    if args.debug:
        logging.basicConfig(level=logging.DEBUG , force=True)

    as_parser = AsCandidateParser()
    as_candidate = as_parser.parse(args.as_config)
    logging.info(f"Parsed AS candidate configuration: {as_candidate}")

    # Load relationships from the JSON configuration, with CLI overrides when provided.
    relationships = args.relationships or as_candidate.relationships_path

    if relationships:
        RipeDb.reset_instance()
        RipeDb.get_instance().load_local_relationships(relationships)
        logging.info(f"Loaded local relationships from `{relationships}`")

    # Resolve the MRT RIB dump path from the JSON configuration or CLI arguments.
    rib_dump_file = os.path.abspath(args.rib_dump or as_candidate.rib_dump_path or DEFAULT_RIB)
    table_dump = TableDump(rib_dump_file)
    logging.info(f"Loaded MRT Table Dump from `{rib_dump_file}`")

    Timer.reset()

    # Build the topology from the parsed AS candidate configuration.
    topology = Topology(as_candidate=as_candidate, table_dump=table_dump)
    logging.info(f"Created topology with {len(list(topology.all()))} nodes")

    net_scenario_name = args.name or f"as{as_candidate.local_as}"
    net_scenario_manager = NetworkScenarioManager()
    net_scenario = net_scenario_manager.build_from_topology(net_scenario_name, topology)

    bgp_config = BgpConfiguration(topology)
    bgp_config.apply_to_network_scenario(net_scenario)

    for router in topology.get_candidate_routers():
        vendor_config = topology.get_candidate_router_config(router.machine_name)
        startup_path = topology.get_candidate_router_startup(router.machine_name)
        if startup_path:
            if vendor_config:
                vendor_config.apply_to_network_scenario(
                    net_scenario,
                    machine_name=router.machine_name,
                    startup_script_path=startup_path
                )
        else:
            if vendor_config:
                vendor_config.apply_to_network_scenario(
                    net_scenario,
                    machine_name=router.machine_name
                )

    logging.info("Deploying network scenario...")
    net_scenario_manager.start_candidate_device(net_scenario, topology=topology)
    net_scenario_manager.start_other_devices(net_scenario, topology=topology)
    logging.success("Network scenario deployed successfully.")

    all_passed = False
    result_lines = []
    try:
        action_manager = ActionManager(exclude=args.exclude_checks.split(','))

        if topology._as_candidate and len(topology._as_candidate.routers) > 0:
            vendor_config = topology._as_candidate.routers[0].vendor_config
        else:
            vendor_config = None

        results = action_manager.start(
            topology._as_candidate,
            topology,
            table_dump,
            net_scenario
        )

        all_passed = all([x.passed() for x in results])

        for result in results:
            result.print(level=args.result_level)
            result_lines.extend(result.format_lines(level=args.result_level))

    except (BgpRuntimeError, ConfigValidationError) as e:
        result_lines.append("Not Converged")
        logging.error(f"Error during validation: {e}")

    Timer.tick("Undeploy")

    table_dump.close()

    net_scenario_manager.undeploy(net_scenario)

    routers = [n for n_name, n in topology.all() if isinstance(n, BgpRouter)]
    seen = set()
    clients = []
    for _, node in topology.all():
        if isinstance(node, BgpRouter):
            for neighbours in node.neighbours.values():
                for neigh in neighbours.values():
                    n = neigh.neighbour
                    if isinstance(n, Client) and id(n) not in seen:
                        seen.add(id(n))
                        clients.append(n)
    names_w = max(
        0,
        *[len(r.machine_name) for r in routers],
        *[len(c.machine_name) for c in clients]
    )
    devices = ["=" * (names_w + 22)]
    devices.append(f"  ROUTERS ({len(routers)}):")
    for r in sorted(routers, key=lambda x: x.machine_name):
        devices.append(f"    {r.machine_name}")
    devices.append("")
    devices.append(f"  CLIENTS ({len(clients)}):")
    for c in sorted(clients, key=lambda x: x.machine_name):
        devices.append(f"    {c.machine_name}")
    devices.append("=" * (names_w + 22))
    device_info = "\n".join(devices) + "\n"

    # Print a concise summary of the validation results and deployed devices.
    summary = Timer.format_summary()
    Timer.print_summary()
    sys.stdout.write(device_info)

    if args.file:
        d = os.path.dirname(args.file)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.file, 'w') as f:
            f.write("\n".join(result_lines) + "\n" + summary + "\n" + device_info)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    set_logging()
    sys.exit(main(parse_args()))