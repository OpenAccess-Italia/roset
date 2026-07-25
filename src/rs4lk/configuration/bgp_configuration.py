import itertools
import logging

from Kathara.model.Lab import Lab
from Kathara.model.Machine import Machine

from ..foundation.configuration.configuration_applier import ConfigurationApplier
from ..model.topology import BgpRouter, Topology, INTERNET_AS_NUM

# --------------------------- Start of BGP configuration templates -----------------------------------------------

ZEBRA_CONFIG = \
    """hostname frr
password frr
enable password frr"""

BGPD_BASIC_CONFIG = \
    """
router bgp {as_number}
 no bgp default ipv4-unicast
 no bgp ebgp-requires-policy
 no bgp network import-check
{neighbour_config}"""

BGPD_FILTERS = \
    """
ip prefix-list DEF_ONLY_4 permit 0.0.0.0/0
ip prefix-list DEF_ONLY_4 deny any

ip prefix-list DEF_ONLY_6 permit ::/0
ip prefix-list DEF_ONLY_6 deny any"""

IPV6_ROUTE_MAP = \
    """
route-map PREFER_IPV6_GLOBAL permit 10
  set ipv6 next-hop prefer-global"""

BGPD_NEIGHBOUR_CONFIG = """
 neighbor {ip} remote-as {as_num}
 neighbor {ip} timers connect 10"""
BGPD_NEIGHBOR_FILTER = " neighbor {ip} prefix-list DEF_ONLY_{v} out"
BGPD_NEIGHBOR_MULTIHOP = " neighbor {ip} ebgp-multihop 255"

BGPD_AF_BLOCK = """
 address-family ipv{v} unicast
{neighbours_activate}
{neighbours_route_maps}
{networks_announcements}
 exit-address-family"""
BGPD_NEIGHBOUR_ACTIVATE = "  neighbor {ip} activate"
BGPD_NEIGHBOR_IPV6_ROUTE_MAP = "  neighbor {ip} route-map PREFER_IPV6_GLOBAL in"
BGPD_NETWORK_ANNOUNCEMENT = "  network %s"


# ---------------------------  End of BGP configuration templates -----------------------------------------------


class BgpConfiguration(ConfigurationApplier):
    __slots__ = ['_topology']

    def __init__(self, topology: Topology) -> None:
        self._topology: Topology = topology

    def apply_to_network_scenario(self, net_scenario: Lab) -> None:
        for as_num, bgp_router in self._topology.all():
            if not isinstance(bgp_router, BgpRouter) or bgp_router.relationship is None:
                continue

            if bgp_router.is_candidate():
                continue

            router_name = bgp_router.machine_name
            if not net_scenario.has_machine(router_name):
                continue

            router: Machine = net_scenario.get_machine(router_name)

            self._configure_device(router, bgp_router)

    def _configure_device(self, device: Machine, bgp_router: BgpRouter) -> None:
        logging.info(f"Configuring BGP in device `{device.name}`...")

        device.add_meta('image', 'kathara/frr:9')

        device.create_file_from_list(
            ['zebra=yes', 'bgpd=yes'], '/etc/frr/daemons'
        )

        zebra_config = ZEBRA_CONFIG.split('\n')
        if bgp_router.is_provider():
            zebra_config.extend(['ip nht resolve-via-default', 'ipv6 nht resolve-via-default'])
        device.create_file_from_list(
            zebra_config, '/etc/frr/zebra.conf'
        )

        self._write_device_configuration(device, bgp_router)

        with device.lab.fs.open(f"{device.name}.startup", 'a') as startup:
            startup.write('systemctl start frr')

    @staticmethod
    def _write_device_configuration(device: Machine, bgp_router: BgpRouter) -> None:
        bgpd_configuration = ZEBRA_CONFIG.split('\n')

        if bgp_router.is_provider():
            bgpd_configuration.append(BGPD_FILTERS)

        all_ips = {4: [], 6: []}
        neighbour_config = []
        for iface_idx, neighbours in bgp_router.neighbours.items():
            for neighbour in neighbours.values():
                neighbour_ips = neighbour.get_neighbours_ips(is_public=True)
                all_ips[4].extend(map(lambda x: x[1].ip, neighbour_ips[4]))
                all_ips[6].extend(map(lambda x: x[1].ip, neighbour_ips[6]))

                neighbour_router = neighbour.neighbour
                for (_, iface_ip, _) in list(itertools.chain.from_iterable(neighbour_ips.values())):
                    neighbour_config.append(
                        BGPD_NEIGHBOUR_CONFIG.format(ip=iface_ip.ip, as_num=neighbour_router.identifier)
                    )
                    if bgp_router.is_provider() and \
                            (not neighbour_router.is_candidate() and neighbour_router.identifier != INTERNET_AS_NUM):
                        # We do not filter prefixes towards candidate and Internet
                        neighbour_config.append(
                            BGPD_NEIGHBOR_FILTER.format(ip=iface_ip.ip, v=iface_ip.ip.version)
                        )

        for remote_as_num, remote_v_ips in bgp_router.remote_neighbours.items():
            all_ips[4].extend(remote_v_ips[4])
            all_ips[6].extend(remote_v_ips[6])
            for remote_ip in list(itertools.chain.from_iterable(remote_v_ips.values())):
                neighbour_config.append(
                    BGPD_NEIGHBOUR_CONFIG.format(ip=remote_ip, as_num=remote_as_num)
                )
                neighbour_config.append(BGPD_NEIGHBOR_MULTIHOP.format(ip=remote_ip))

        if len(all_ips[6]) > 0:
            bgpd_configuration.append(IPV6_ROUTE_MAP)

        basic_config = BGPD_BASIC_CONFIG.format(
            as_number=bgp_router.identifier,
            neighbour_config="\n".join(neighbour_config)
        )

        bgpd_configuration.extend(basic_config.split('\n'))

        for v, v_ips in all_ips.items():
            unique_v_ips = set(v_ips)
            if unique_v_ips:
                neighbour_activates = "\n".join([BGPD_NEIGHBOUR_ACTIVATE.format(ip=x) for x in unique_v_ips])
                network_announcements = "\n".join(
                    [BGPD_NETWORK_ANNOUNCEMENT % network for network in bgp_router.announced_networks[v]]
                )
                neighbours_route_maps = ""
                if v == 6:
                    neighbours_route_maps = "\n".join([BGPD_NEIGHBOR_IPV6_ROUTE_MAP.format(ip=x) for x in unique_v_ips])

                bgpd_configuration.append(
                    BGPD_AF_BLOCK.format(
                        v=v,
                        neighbours_activate=neighbour_activates,
                        neighbours_route_maps=neighbours_route_maps,
                        networks_announcements=network_announcements
                    )
                )

        device.create_file_from_list(bgpd_configuration, '/etc/frr/bgpd.conf')
