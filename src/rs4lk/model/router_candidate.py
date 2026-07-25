from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..foundation.configuration.vendor_configuration import VendorConfiguration

from .topology import BgpRouter


class RouterCandidate(BgpRouter):
    __slots__ = ['router_name', 'vendor', 'config_path', 'vendor_config', 'startup_script_path', 'docker_image']

    def __init__(self, router_name: str, vendor: str, config_path: str, local_as: int,
                 vendor_config: 'VendorConfiguration | None' = None,
                 startup_script_path: str | None = None,
                 docker_image: str | None = None) -> None:
        super().__init__(local_as, None)
        self.router_name: str = router_name
        self.vendor: str = vendor
        self.config_path: str = config_path
        self.vendor_config: 'VendorConfiguration | None' = vendor_config
        self.startup_script_path: str | None = startup_script_path
        self.docker_image: str | None = docker_image

    @property
    def name(self) -> str:
        return self.machine_name

    @property
    def machine_name(self) -> str:
        return f"as{self.identifier}_{self.router_name}"

    def __repr__(self) -> str:
        return f"RouterCandidate {self.router_name} (as{self.identifier}, vendor={self.vendor})"
