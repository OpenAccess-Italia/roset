import ipaddress
import logging
from abc import ABC, abstractmethod

from sortedcontainers import SortedDict

from .commands_mixin import CommandsMixin
from .configuration_applier import ConfigurationApplier
from .vendor_format_parser import VendorFormatParser
from ..exceptions import ConfigError
from ...model.bgp_session import BgpSession, BgpPeering
from ...model.interface import Interface, VlanInterface
from ...utils import urlsafe_hash


class VendorConfiguration(ConfigurationApplier, CommandsMixin, VendorFormatParser, ABC):
    __slots__ = ['name', 'path', 'interfaces', 'local_as', 'sessions', '_lines', 'iface_to_iface_idx', 'docker_image']

    def __init__(self) -> None:
        self.name: str | None = None
        self.path: str | None = None
        self.interfaces: dict[str, Interface] | None = {}
        self.local_as: int = 0
        self.sessions: dict[int, BgpSession] | None = {}
        self.docker_image: str | None = None

        self._lines: list[str] | None = None
        self.iface_to_iface_idx: SortedDict[str, int] = SortedDict({})

    def load(self) -> None:
        with open(self.path, 'r') as config_file:
            self._lines = config_file.readlines()

        if not self._lines:
            raise ConfigError("Empty config file")

        self.name = urlsafe_hash(self.path)

        self._remap_interfaces()
        self._filter_bgp_sessions()
        self._infer_bgp_dc_sessions()
        self._set_bgp_sessions_interfaces()

    @abstractmethod
    def get_image(self) -> str:
        raise NotImplementedError("You must implement `get_image` method.")

    @abstractmethod
    def _remap_interfaces(self) -> None:
        raise NotImplementedError("You must implement `_remap_interfaces` method.")

    def _filter_bgp_sessions(self) -> None:
        filtered_sessions = {}

        for remote_as, session in self.sessions.items():
            if not self._is_valid_session(remote_as):
                continue

            filtered_sessions[remote_as] = session

        self.sessions = filtered_sessions

    def _is_valid_session(self, remote_as: int) -> bool:
        if 64000 <= remote_as <= 131071:
            logging.warning(f"Skipping session with AS{remote_as} is in reserved range 64000-131071.")
            return False
        if self.local_as == remote_as:
            logging.warning(f"Not skipping session with AS{remote_as} but is a iBGP peering.")
            return True

        return True

    def _infer_bgp_dc_sessions(self) -> None:
        logging.info("Inferring directly connected BGP sessions.")

        for session in self.sessions.values():
            iface = None
            for peering in session.peerings:
                iface, local_ip = self._get_interface_for_peering(peering)
                if not iface:
                    continue

                peering.local_ip = local_ip
                iface_name = iface.phy.name if isinstance(iface, VlanInterface) else iface.name
                peering.iface_idx = self.iface_to_iface_idx[iface_name]

            session.iface = iface

        logging.debug(f"Resulting sessions: {self.sessions}")

    def _get_interface_for_peering(self, bgp_peering: BgpPeering) \
            -> (Interface | None, ipaddress.IPv4Interface | ipaddress.IPv6Interface | None):
        selected_iface = None
        selected_iface_ip = None
        last_plen = -1

        # Do LPM algorithm
        for iface in self.interfaces.values():
            for iface_ip in iface.addresses:
                if bgp_peering.remote_ip.version != iface_ip.network.version:
                    continue

                if bgp_peering.remote_ip in iface_ip.network and iface_ip.network.prefixlen > last_plen:
                    selected_iface = iface
                    selected_iface_ip = iface_ip
                    last_plen = iface_ip.network.prefixlen

        if selected_iface:
            return selected_iface, selected_iface_ip

        logging.warning(f"Cannot find interface for directly connected peering with AS{bgp_peering.session.remote_as}.")

        return None, None

    def _set_bgp_sessions_interfaces(self) -> None:
        for session in self.sessions.values():
            if session.iface:
                session_interface = session.iface.phy.name \
                    if isinstance(session.iface, VlanInterface) else session.iface.name
                session.iface_idx = self.iface_to_iface_idx[session_interface]
                session.vlan = session.iface.vlan if isinstance(session.iface, VlanInterface) else None
