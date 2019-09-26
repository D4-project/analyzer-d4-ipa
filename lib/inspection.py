#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Inspection library for the analyzer
#
# Copyright (C) 2019  Romain Kieffer
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from pyshark import FileCapture
from glob import glob


unassigned_icmp_types = ['1', '2', '7'] + [str(i) for i in range(44, 253)]
robustness_icmp_types = [str(i) for i in range(20, 30)]
deprecated_icmp_types = ['4', '6', '15', '16', '17', '18'] + [str(i) for i in range(30, 40)]
icmp_type_dict = {
    '0': 'echo-rep',
    '3': 'dest-unreachable',
    '4': 'source-quench',
    '5': 'redirect',
    '6': 'alternate-host-add',
    '7': 'unassigned',
    '8': 'echo',
    '9': 'router-advertisement',
    '10': 'router-solicitation',
    '11': 'time-exceed',
    '12': 'param-pb',
    '13': 'timestamp',
    '14': 'timestamp-rep',
    '15': 'info-request',
    '16': 'info-reply',
    '17': 'address-mask-req',
    '18': 'address-mask-rep',
    '30': 'traceroute',
    '31': 'mobile-host-redirect',
    '32': 'datagram-conversion-error',
    '33': 'ipv6-where',
    '34': 'ipv6-here',
    '35': 'mobile-register-req',
    '36': 'mobile-register-rep',
    '37': 'dn-req',
    '38': 'dn-rep',
    '39': 'skip',
    '40': 'photuris',
    '41': 'experimental-mobility',
    '42': 'extended-echo-req',
    '43': 'extended-echo-rep',
    '253': 'rfc3692-1',
    '254': 'rfc3692-2',
}

unassigned_proto = [str(i) for i in range(143, 253)]
proto_dict = {
    '0': 'hopopt',
    '1': 'icmp',
    '2': 'igmp',
    '6': 'tcp',
    '8': 'egp',
    '10': 'bbn-rcc-mon',
    '15': 'xnet',
    '16': 'chaos',
    '17': 'udp',
    '18': 'mux',
    '23': 'trunk-1',
    '24': 'trunk-2',
    '25': 'leaf-1',
    '27': 'rdp',
    '28': 'irtp',
    '29': 'iso-tp4',
    '32': 'merit-inp',
    '33': 'dccp',
    '34': '3pc',
    '38': 'idpr-cmtp',
    '41': 'ipv6',
    '42': 'sdrp',
    '47': 'gre',
    '50': 'esp',
    '51': 'ah',
    '54': 'narp',
    '55': 'mobile',
    '56': 'tlsp',
    '58': 'ipv6-icmp',
    '59': 'ipv6-nonxt',
    '61': 'any_host_internal_protocol',
    '62': 'cftp',
    '63': 'any_local_network',
    '67': 'ippc',
    '69': 'sat-mon',
    '70': 'visa',
    '72': 'cpnx',
    '75': 'pvp',
    '76': 'br-sat-mon',
    '78': 'wb-mon',
    '84': 'iptm',
    '85': 'nsfnet-igp',
    '93': 'ax25',
    '97': 'etherip',
    '98': 'encap',
    '104': 'aris',
    '106': 'qnx',
    '113': 'pgm',
    '115': 'l2tp',
    '117': 'iatp',
    '119': 'srp',
    '124': 'isisv4',
    '135': 'mobility-header',
    '137': 'mpls-in-ip',
    }


def get_raw_cap(path_to_cap: str):
    return FileCapture(input_file=path_to_cap, display_filter='icmp', use_json=True, include_raw=True)


def get_cap(path_to_cap: str):
    return FileCapture(input_file=path_to_cap, display_filter='icmp')


def get_files(path) -> list:
    caps = glob(path)
    return caps


def init_cap_list(dataset_path: str) -> list:
    if dataset_path[-1] == '/':
        extension = '*.gz'
    else:
        extension = '/*.gz'
    cap_path = dataset_path + extension
    caps = get_files(cap_path)
    caps.sort()
    return caps


def list_caps(state: str, redis):
    caps = []
    b_list = redis.lrange(state, 0, -1)
    for item in b_list:
        caps.append(item.decode())
    return caps


def get_protocol(packet):
    if 'ip_proto' in packet.icmp.field_names:
        protocol = str(packet.icmp.ip_proto)
        if protocol in unassigned_proto:
            return protocol + ' (unassigned)'
        ip_proto = proto_dict[protocol]
    else:
        return 'nbs-icmp'
    return protocol + ' : ' + str(ip_proto)


def get_icmp_payload(packet):
    if 'data' in packet.icmp.field_names:
        return str(packet.icmp.data)
    elif packet.icmp.field_names != ['type', 'code', 'checksum', 'checksum_status', 'ident', 'seq', 'seq_le']:
        return 'No data'


def get_port(packet, protocol, endpoint):
    if protocol == 'tcp':
        if endpoint == 'src':
            return packet.icmp.tcp_srcport
        elif endpoint == 'dst':
            return packet.icmp.tcp_dstport
    elif protocol == 'udp':
        if endpoint == 'src':
            return packet.icmp.udp_srcport
        elif endpoint == 'dst':
            return packet.icmp.udp_dstport
    else:
        return 0


def get_src_port(packet):
    proto = get_protocol(packet)
    return get_port(packet, proto, 'src')


def get_dst_port(packet):
    proto = get_protocol(packet)
    return get_port(packet, proto, 'dst')


def get_icmp_ip(packet):
    proto = get_protocol(packet)
    if 'ip_src' in packet.icmp.field_names:
        return packet.icmp.ip_src


def list_sources_and_targets(cap):
    sources, targets = [], []
    for packet in cap:
        src_port_tuple = get_src_port(packet)
        src = (packet.icmp.ip_src, src_port_tuple)
        dst_port_tuple = get_dst_port(packet)
        dst = (packet.icmp.ip_dst, dst_port_tuple)
        if src not in sources:
            sources.append(src)
        if dst not in targets:
            targets.append(dst)
    return sources, targets


def check_icmp_checksum(data):
    hex_sum = 0
    split_data = [data[i:i + 4] for i in range(0, len(data), 4)]
    checksum = hex(int(split_data[1], 16))
    split_data[1] = '0000'
    for i in range(len(split_data)):
        hex_sum += int(split_data[i], 16)
    mask = (1 << hex_sum.bit_length()) - 1
    res = hex(hex_sum ^ mask)
    if res == checksum:
        return 'good'
    else:
        return 'bad'
