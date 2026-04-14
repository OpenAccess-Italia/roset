import logging
import re

import requests


class RipeDb:
    __slots__ = ['_as_rules_cache']

    URL: str = 'https://rest.db.ripe.net/search.txt?query-string=AS%d&flags=no-referenced&flags=no-irt&source=RIPE'
    RPSL_REGEX = re.compile(r"^(?P<key>.*):\s+(?P<value>.*)$")

    __instance: 'RipeDb' = None

    @staticmethod
    def get_instance() -> 'RipeDb':
        if RipeDb.__instance is None:
            RipeDb()

        return RipeDb.__instance

    def __init__(self) -> None:
        if RipeDb.__instance is not None:
            raise InstantiationError("This class is a singleton!")
        else:
            self._as_rules_cache: dict[int, (list[str], list[str])] = {}

            RipeDb.__instance = self

    def get_local_as_rules(self, as_num: int) -> (list[str], list[str]):
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
