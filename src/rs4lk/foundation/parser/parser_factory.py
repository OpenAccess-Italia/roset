from .grammar_parser import Parser
from ...foundation.factory.Factory import Factory


class ParserFactory(Factory):
    def __init__(self) -> None:
        self.module_template: str = "rs4lk.parser.%s"
        self.name_template: str = "%s_parser"

    def get_class_from_name(self, os_name: str) -> Parser.__class__:
        return self.get_class((os_name.lower(),), (os_name.lower(),))
