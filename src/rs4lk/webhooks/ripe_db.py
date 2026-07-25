import json
import logging
import re

import requests


class RipeDb:
    __slots__ = ['_as_rules_cache', '_local_relationships', '_local_as_rules']

    URL: str = 'https://rest.db.ripe.net/search.txt?query-string=AS%d&flags=no-referenced&flags=no-irt&source=RIPE'
    RPSL_REGEX = re.compile(r"^(?P<key>.*):\s+(?P<value>.*)$")

    __instance: 'RipeDb' = None

    @staticmethod
    def get_instance() -> 'RipeDb':
        if RipeDb.__instance is None:
            RipeDb()

        return RipeDb.__instance

    @staticmethod
    def reset_instance() -> None:
        RipeDb.__instance = None

    def __init__(self) -> None:
        if RipeDb.__instance is not None:
            raise InstantiationError("This class is a singleton!")
        else:
            self._as_rules_cache: dict[int, (list[str], list[str])] = {}
            self._local_relationships: dict = {}
            self._local_as_rules: dict={}

            RipeDb.__instance = self

    def load_local_relationships(self, file_path: str) -> None:
        logging.info(f"Loading local relationships from `{file_path}`...")
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            self._local_relationships = data.get('relationships', data)
            self._local_as_rules = data.get('as_rules', {})
        except FileNotFoundError:
            logging.warning(f"Local relationships file not found: {file_path}")
            self._local_relationships = {}
            self._local_as_rules = {}
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in local relationships file: {e}")
            self._local_relationships = {}
            self._local_as_rules = {}

    def get_local_relationship(self, local_as: int, remote_as: int) -> int | None:
        as_key = f"AS{local_as}"
        if as_key not in self._local_relationships:
            return None
        
        relationships = self._local_relationships[as_key]
        remote_key = f"AS{remote_as}"
        
        if remote_key not in relationships:
            return None
        
        rel_str = relationships[remote_key].lower()
        if rel_str == "provider":
            return 1
        elif rel_str == "customer":
            return 2
        elif rel_str == "peer":
            return 0
        return None

    def get_local_as_rules(self, as_num: int) -> (list[str], list[str]):
        as_key = f"AS{as_num}"
        if hasattr(self, '_local_as_rules') and as_key in self._local_as_rules:
            rules = self._local_as_rules[as_key]
            import_rules = [f"from AS{t} accept ANY" for t in rules.get('transits', [])]
            return import_rules, []

        if as_num in self._as_rules_cache:
            return self._as_rules_cache[as_num]

        logging.info(f"Querying RIPE DB for AS{as_num}.")

        response = requests.get(url=self.URL % as_num)
        response.raise_for_status()

        import_rules = []
        export_rules = []

        lines = response.text.split('\n')
        for line in lines:
            matches = self.RPSL_REGEX.search(line.strip())

            if not matches:
                continue

            key = matches.group("key").strip()
            value = matches.group("value").strip()

            if 'import' in key:
                import_rules.append(value)
            if 'export' in key:
                export_rules.append(value)

        self._as_rules_cache[as_num] = (import_rules, export_rules)

        return import_rules, export_rules
