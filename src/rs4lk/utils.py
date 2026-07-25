import base64
import hashlib
import logging
import re
import sys
import time


# General Helpers
def urlsafe_hash(string: str) -> str:
    string = re.sub(r'[^\x00-\x7F]+', '', string)
    return base64.urlsafe_b64encode(hashlib.md5(string.encode('utf-8', errors='ignore')).digest())[:-2] \
        .decode('utf-8') \
        .replace('-', '').replace('_', '')


# Network IP Helpers
def aggregate_v4_6_networks(nets: dict[int, set]) -> None:
    for v, networks in nets.items():
        nets[v] = aggregate_networks(networks)


def aggregate_networks(networks: set) -> set:
    aggregated_networks = set(networks)
    for network in networks:
        for prefix in range(network.prefixlen - 1, 0, -1):
            super_network = network.supernet(new_prefix=prefix)
            if super_network in aggregated_networks and network in aggregated_networks:
                aggregated_networks.remove(network)

    return aggregated_networks


class Timer:
    _marks: list[tuple[str, float]] = []

    @classmethod
    def tick(cls, label: str) -> None:
        cls._marks.append((label, time.time()))

    @classmethod
    def print_summary(cls) -> None:
        sys.stdout.write(cls.format_summary())

    @classmethod
    def format_summary(cls) -> str:
        if not cls._marks:
            return ""

        start = cls._marks[0][1]
        total = cls._marks[-1][1] - start

        name_w = max(len(m[0]) for m in cls._marks) + 2
        sep = "=" * (name_w + 17)
        out = [f"\n{sep}", f"  {'PHASE':<{name_w}}  {'DURATION':>9}", sep]

        prev_ts = start
        for label, ts in cls._marks:
            dur = ts - prev_ts
            out.append(f"  {label:<{name_w}}  {dur:>7.2f}s")
            prev_ts = ts

        out.append(sep)
        out.append(f"  {'TOTAL':<{name_w}}  {total:>7.2f}s\n")
        return "\n".join(out) + "\n"

    @classmethod
    def reset(cls) -> None:
        cls._marks.clear()
