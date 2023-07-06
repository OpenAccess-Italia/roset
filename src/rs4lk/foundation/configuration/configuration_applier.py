from abc import ABC, abstractmethod

from Kathara.model.Lab import Lab


class ConfigurationApplier(ABC):
    @abstractmethod
    def apply_to_network_scenario(self, net_scenario: Lab) -> None:
        raise NotImplementedError("You must implement `apply_to_network_scenario` method.")
