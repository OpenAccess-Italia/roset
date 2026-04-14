import logging
import os.path

from ..foundation.configuration.vendor_configuration import VendorConfiguration
from ..foundation.configuration.vendor_configuration_factory import VendorConfigurationFactory
from ..foundation.exceptions import ClassNotFoundError, ConfigError
from ..foundation.parser.grammar_parser import Parser
from ..foundation.parser.parser_factory import ParserFactory


class GrammarParser:
    __slots__ = ['_parsers']

    def __init__(self) -> None:
        self._parsers: dict = {}

    def parse(self, config_path: str, name: str) -> VendorConfiguration:
        full_path = os.path.abspath(config_path)

        logging.info(f"Parsing configuration `{full_path}` with format `{name}`...")

        parser = self._get_or_new_parser(name)

        vendor_config = VendorConfigurationFactory().create_from_name(name)
        vendor_config.path = full_path

        parser.set_vendor_config(vendor_config)
        parser.parse(full_path)

        vendor_config.load()

        return vendor_config

    def _get_or_new_parser(self, name: str) -> Parser:
        if name in self._parsers:
            return self._parsers[name]

        try:
            parser_class = ParserFactory().get_class_from_name(name)

            parser = parser_class()

            self._parsers[name] = parser
        except ClassNotFoundError:
            raise ConfigError(f"Format `{name}` is not supported!")

        return parser
