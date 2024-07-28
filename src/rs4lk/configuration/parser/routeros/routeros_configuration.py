import ipaddress

from antlr4 import *
from future.moves import sys

from RouterosLexer import RouterosLexer
from RouterosListener import RouterosListener
from RouterosParser import RouterosParser


class RouterosCustomListener(RouterosListener):

    def __init__(self, configuration):
        super().__init__()
        self.configuration: RouterosConfiguration = configuration

    def enterInterfaceName(self, ctx: RouterosParser.InterfaceNameContext):
        self.configuration.interfaces[str(ctx.INTERFACE_NAME())] = {}

    def enterVlanConfig(self, ctx: RouterosParser.VlanConfigContext):
        vlan_name = None
        vlan_id = None
        interface = None
        for i in range(0, ctx.getChildCount()):
            key_value: RouterosParser.KeyValuePairContext = ctx.keyValuePair(i)
            if key_value:
                key = key_value.key().getText()
                value = key_value.value().getText()
                if key == "name":
                    vlan_name = value
                if key == "vlan-id":
                    vlan_id = int(value)
                if key == "interface":
                    interface = value
        self.configuration.interfaces[vlan_name] = {
            "interface": interface,
            "vlan_id": vlan_id
        }

    def enterIpv4Config(self, ctx: RouterosParser.Ipv4ConfigContext):
        interface = None
        address = None
        for i in range(0, ctx.getChildCount()):
            key_value: RouterosParser.KeyValuePairContext = ctx.keyValuePair(i)
            if key_value:
                key = key_value.key().getText()
                value = key_value.value().getText()

                if key == "interface":
                    interface = value
                if key == "address":
                    address = ipaddress.ip_network(value, strict=False)
        if interface not in self.configuration.interfaces:
            self.configuration.interfaces[interface] = {}
        ip_ver = f"ipv{address.version}"
        if ip_ver not in self.configuration.interfaces[interface]:
            self.configuration.interfaces[interface][ip_ver] = []
        self.configuration.interfaces[interface][ip_ver].append(address)

    def enterBgpPeeringConfig(self, ctx: RouterosParser.BgpPeeringConfigContext):
        role = None
        remote_as = None
        local_address = None
        remote_address = None

        for i in range(0, ctx.getChildCount()):
            key_value: RouterosParser.KeyValuePairContext = ctx.keyValuePair(i)
            if key_value:
                key = key_value.key().getText()
                value = key_value.value().getText()
                if key == "local.address":
                    local_address = ipaddress.ip_network(value, strict=False)
                if key == "remote.address":
                    remote_address = ipaddress.ip_network(value, strict=False)
                if key == "as":
                    self.configuration.local_as = int(value)
                if key == ".as":
                    remote_as = int(value)
                if key == ".role":
                    role = value
        if role != "ebgp":
            return
        if remote_as and local_address and remote_address:
            self.configuration.peerings.append({
                'remote_as': remote_as,
                'local_ip': local_address,
                'remote_ip': remote_address,
            })


class RouterosConfiguration:
    def __init__(self, config_path: str):
        self._config_path = config_path
        self.interfaces: dict[str, dict] = {}
        self.peerings: list[dict] = []
        self.local_as = None

        # Parse configuration using ANTLR4 autogenerated parser
        input_stream = FileStream(config_path)
        lexer = RouterosLexer(input_stream)
        stream = CommonTokenStream(lexer)
        parser = RouterosParser(stream)
        tree = parser.config()
        self.rule_names = parser.ruleNames

        # Use a custom listener to walk the tree and populate the configuration
        listener = RouterosCustomListener(self)
        walker = ParseTreeWalker()
        walker.walk(listener, tree)


if __name__ == '__main__':
    config = RouterosConfiguration(sys.argv[1])
    print("Interfaces")
    print(config.interfaces)
    print("peerings")
    print(config.peerings)
    print("local_as", config.local_as)
