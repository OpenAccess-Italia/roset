from abc import ABC, abstractmethod

from ..configuration.vendor_configuration import VendorConfiguration


class Parser(ABC):
    __slots__ = ['_configuration']

    def __init__(self) -> None:
        self._configuration: VendorConfiguration | None = None

    def parse(self, path: str) -> None:
        with open(path, 'r') as config_file:
            content = config_file.read()

        self._parse_interfaces(content)
        self._parse_bgp(content)

        self._on_complete()

    @abstractmethod
    def _parse_interfaces(self, content: str) -> None:
        raise NotImplementedError("You must implement `_parse_interfaces` method.")

    @abstractmethod
    def _parse_bgp(self, content: str) -> None:
        raise NotImplementedError("You must implement `_parse_bgp` method.")

    def _on_complete(self) -> None:
        pass

    def set_vendor_config(self, conf: VendorConfiguration) -> None:
        self._configuration = conf
