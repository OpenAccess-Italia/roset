from abc import ABC, abstractmethod

from Kathara.model.Lab import Lab

from ..configuration.vendor_configuration import VendorConfiguration
from ...model.topology import Topology
from ...mrt.table_dump import TableDump


class Action(ABC):
    @abstractmethod
    def verify(
            self, config: VendorConfiguration, table_dump: TableDump, topology: Topology | None = None,
            net_scenario: Lab | None = None
    ) -> 'ActionResult':
        raise NotImplementedError("You must implement `verify` method.")

    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError("You must implement `name` method.")

    @abstractmethod
    def display_name(self) -> str:
        raise NotImplementedError("You must implement `display_name` method.")
