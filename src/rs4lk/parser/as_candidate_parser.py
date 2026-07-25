import json
import logging
import os.path

from ..foundation.exceptions import ConfigError
from ..model import AsCandidate, RouterCandidate
from .grammar_parser import GrammarParser


class AsCandidateParser:
    def __init__(self) -> None:
        self._grammar_parser = GrammarParser()

    def parse(self, json_path: str) -> AsCandidate:
        full_path = os.path.abspath(json_path)
        logging.info(f"Parsing AS candidate configuration from `{full_path}`...")

        json_dir = os.path.dirname(full_path)

        with open(full_path, 'r') as f:
            data = json.load(f)

        self._validate_json_schema(data, full_path)

        local_as = data['local_as']

        relationships_path = data.get('relationships')
        if relationships_path and not os.path.isabs(relationships_path):
            relationships_path = os.path.join(json_dir, relationships_path)

        rib_dump_path = data.get('rib_dump')
        if rib_dump_path and not os.path.isabs(rib_dump_path):
            rib_dump_path = os.path.join(json_dir, rib_dump_path)

        as_candidate = AsCandidate(local_as, relationships_path=relationships_path, rib_dump_path=rib_dump_path)

        for router_data in data['routers']:
            router = self._parse_router(router_data, local_as, json_dir)
            as_candidate.add_router(router)

        logging.info(f"Parsed AS candidate: {as_candidate}")
        return as_candidate

    def _validate_json_schema(self, data: dict, json_path: str) -> None:
        if 'local_as' not in data:
            raise ConfigError(f"Missing 'local_as' in {json_path}")

        if 'routers' not in data:
            raise ConfigError(f"Missing 'routers' in {json_path}")

        if not isinstance(data['routers'], list):
            raise ConfigError(f"'routers' must be a list in {json_path}")

        if len(data['routers']) == 0:
            raise ConfigError(f"At least one router must be defined in {json_path}")

        for i, router in enumerate(data['routers']):
            for field in ['name', 'vendor', 'config_path']:
                if field not in router:
                    raise ConfigError(f"Router {i} missing required field '{field}' in {json_path}")

    def _parse_router(self, router_data: dict, expected_as: int, json_dir: str) -> RouterCandidate:
        name = router_data['name']
        vendor = router_data['vendor']
        config_path = router_data['config_path']
        if not os.path.isabs(config_path):
            config_path = os.path.join(json_dir, config_path)

        startup_script_path = router_data.get('startup_script_path')
        if startup_script_path and not os.path.isabs(startup_script_path):
            startup_script_path = os.path.join(json_dir, startup_script_path)

        docker_image = router_data.get('docker_image')

        vendor_config = self._grammar_parser.parse(config_path, vendor)
        if docker_image:
            vendor_config.docker_image = docker_image

        if vendor_config.local_as != expected_as:
            raise ConfigError(
                f"Router '{name}' has local_as={vendor_config.local_as} in config, "
                f"expected AS{expected_as} from JSON"
            )

        router = RouterCandidate(
            router_name=name,
            vendor=vendor,
            config_path=config_path,
            local_as=vendor_config.local_as,
            vendor_config=vendor_config,
            startup_script_path=startup_script_path,
            docker_image=docker_image
        )

        return router
