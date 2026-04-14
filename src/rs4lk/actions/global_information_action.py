from Kathara.model.Lab import Lab

from ..foundation.actions.action import Action
from ..foundation.actions.action_result import ActionResult, SUCCESS, ERROR
from ..foundation.configuration.vendor_configuration import VendorConfiguration
from ..model.rib import RibEntry
from ..model.topology import Topology
from ..mrt.table_dump import TableDump
from ..webhooks.ripe_db import RipeDb


class GlobalInformationAction(Action):
    TIER_1: set[int] = {
        6762, 12956, 2914, 3356, 6453, 701, 6461, 3257, 1299, 3491, 7018, 3320, 5511, 6830, 7922, 174, 6939
    }

    def verify(
            self, config: VendorConfiguration, table_dump: TableDump, topology: Topology | None = None,
            net_scenario: Lab | None = None
    ) -> ActionResult:
        action_result = ActionResult(self)

        as_num = config.local_as

        # Get AS rules found on RIPE DB
        (rir_import_rules, _) = RipeDb.get_instance().get_local_as_rules(as_num)
        rir_transits = self._get_rir_transits(rir_import_rules)

        # Get routes by AS
        rib_entries = table_dump.get_by_as_origin(as_num)
        rib_transits = self._get_rib_transits(rib_entries)

        unexpected_rib_transits = sorted(rib_transits - rir_transits)
        unexpected_rir_transits = sorted(rir_transits - rib_transits)

        if not unexpected_rib_transits and not unexpected_rir_transits:
            action_result.add_result(
                SUCCESS,
                "Excellent work, what declared in the RIR DB matches what was found on the Internet (and vice versa)!"
            )
        else:
            if unexpected_rib_transits:
                action_result.add_result(
                    ERROR,
                    f"The following transits for AS{as_num} are detected on the Internet "
                    f"but not declared in the RIR DB: {', '.join([str(x) for x in unexpected_rib_transits])}"
                )
            if unexpected_rir_transits:
                action_result.add_result(
                    ERROR,
                    f"The following transits for AS{as_num} are declared in the RIR DB "
                    f"but not detected on the Internet: {', '.join([str(x) for x in unexpected_rir_transits])}"
                )

        return action_result

    def _get_rib_transits(self, rib_entries: list[RibEntry]) -> set[int]:
        results = set()

        for entry in rib_entries:
            if entry.peer_as in self.TIER_1 or len(entry.as_path) <= 2:
                continue

            transit_as = entry.as_path[-2]
            results.add(transit_as)

        return results

    def _get_rir_transits(self, rir_import_rules: set[str]) -> set[int]:
        results = set()

        # Remove 'afi XXYY' if it is a mp-import
        rir_import_rules = set([" ".join(x.split(' ')[2:]) if 'afi' in x else x for x in rir_import_rules])

        for import_rule in rir_import_rules:
            if 'accept any' in import_rule.lower():
                # Split by space
                parts = import_rule.split(" ")
                # Get the ASxxx part
                peer_as = int(parts[1].strip().replace("AS", ""))
                results.add(peer_as)

        return results

    def name(self) -> str:
        return "information"

    def display_name(self) -> str:
        return "Global Information"
