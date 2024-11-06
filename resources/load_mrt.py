import argparse
import copy
import os
import sqlite3
from typing import OrderedDict

import mrtparse


class MrtLoader:
    __slots__ = ['path', 'conn']

    def __init__(self, path: str, output_path: str) -> None:
        if not os.path.exists(path):
            raise Exception(f"File `{path}` not found.")

        self.path: str = path
        self.conn: sqlite3.Connection = sqlite3.connect(output_path)

        self._init()

    def _init(self):
        cur = self.conn.cursor()
        cur.execute("""CREATE TABLE rib (
            peer_as bigint(20) NOT NULL,
            network MEDIUMTEXT NOT NULL,
            as_path LONGTEXT NOT NULL
        );""")

    def load_table_dump_v2(self) -> None:
        mrt_reader = mrtparse.Reader(self.path)

        peers = None
        for entry in mrt_reader:
            if entry.err:
                continue

            dump_type = list(entry.data['type']).pop()
            if dump_type != mrtparse.MRT_T['TABLE_DUMP_V2']:
                continue

            dump_subtype = list(entry.data['subtype']).pop()
            if dump_subtype == mrtparse.TD_V2_ST['PEER_INDEX_TABLE']:
                peers = copy.copy(entry.data['peer_entries'])
                break

        cur = self.conn.cursor()

        mrt_reader = mrtparse.Reader(self.path)
        for entry in mrt_reader:
            if entry.err:
                continue

            dump_type = list(entry.data['type']).pop()
            if dump_type != mrtparse.MRT_T['TABLE_DUMP_V2']:
                continue

            dump_subtype = list(entry.data['subtype']).pop()
            if dump_subtype in [
                mrtparse.TD_V2_ST['RIB_IPV4_UNICAST'], mrtparse.TD_V2_ST['RIB_IPV6_UNICAST'],
                mrtparse.TD_V2_ST['RIB_IPV4_MULTICAST'], mrtparse.TD_V2_ST['RIB_IPV6_MULTICAST']
            ]:
                self._parse_table_dump_v2_entry(entry.data, peers, cur)

        self.conn.commit()
        self.conn.close()

    def _parse_table_dump_v2_entry(self, data: OrderedDict, peers: OrderedDict, cur: sqlite3.Cursor) -> None:
        network = f"{data['prefix']}/{data['length']}"

        for entry in data['rib_entries']:
            peer_as = int(peers[entry['peer_index']]['peer_as'])

            to_add = True
            as_path = []
            as4_path = []

            for attr in entry['path_attributes']:
                attr_type = list(attr['type']).pop()
                if attr_type == mrtparse.BGP_ATTR_T['AS_PATH']:
                    for seg in attr['value']:
                        seg_type = list(seg['type']).pop()
                        if seg_type in [mrtparse.AS_PATH_SEG_T['AS_SET'],
                                        mrtparse.AS_PATH_SEG_T['AS_CONFED_SEQUENCE'],
                                        mrtparse.AS_PATH_SEG_T['AS_CONFED_SET']]:
                            to_add = False
                            break

                        as_path += [int(x) for x in seg['value']]
                elif attr_type == mrtparse.BGP_ATTR_T['AS4_PATH']:
                    for seg in attr['value']:
                        seg_type = list(seg['type']).pop()
                        if seg_type in [mrtparse.AS_PATH_SEG_T['AS_SET'],
                                        mrtparse.AS_PATH_SEG_T['AS_CONFED_SEQUENCE'],
                                        mrtparse.AS_PATH_SEG_T['AS_CONFED_SET']]:
                            to_add = False
                            break

                        as4_path += seg['value']

            if to_add:
                final_as_path = []

                if as_path:
                    final_as_path = [int(x) for x in as_path]
                if as4_path:
                    final_as_path = [int(x) for x in as4_path]

                cur.execute(
                    "INSERT INTO rib VALUES (?, ?, ?)",
                    (peer_as, str(network), str(final_as_path))
                )


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('table_dump_file', nargs=1, type=str)
    parser.add_argument('out_file', nargs=1, type=str)

    return parser.parse_args()


def main(args):
    mrt_parser = MrtLoader(os.path.abspath(args.table_dump_file.pop()), os.path.abspath(args.out_file.pop()))
    mrt_parser.load_table_dump_v2()


if __name__ == "__main__":
    main(parse_args())
