#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ICMP Passive Analyzer for D4
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

import redis
import os
import time
import configparser
import logging

from lib.inspection import get_cap, get_protocol, check_icmp_checksum, get_icmp_payload, get_icmp_ip, \
    unassigned_icmp_types, deprecated_icmp_types, get_src_port, get_dst_port, list_caps


class Analyzer:
    """
    Defines a parser to make bulk statistics on a large dataset of network captures.
    """

    def __init__(self, dataset_path: str=None):
        config = configparser.RawConfigParser()
        config.read('../etc/analyzer.conf')

        logging_level = config.get('global', 'logging-level')
        self.logger = logging.getLogger('ipa')
        self.ch = logging.StreamHandler()
        if logging_level == 'DEBUG':
            self.logger.setLevel(logging.DEBUG)
            self.ch.setLevel(logging.DEBUG)
        elif logging_level == 'INFO':
            self.logger.setLevel(logging.INFO)
            self.ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.ch.setFormatter(formatter)
        self.logger.addHandler(self.ch)

        analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
        analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6400))
        self.r = redis.Redis(host=analyzer_redis_host, port=analyzer_redis_port)

        self.dataset = dataset_path
        if not self.dataset:
            self.uuid = config.get('global', 'my-uuid')
            self.queue = "analyzer:1:{}".format(self.uuid)
            self.logger.info("Starting and using FIFO {} from D4 server".format(self.queue))
            d4_server, d4_port = config.get('global', 'd4-server').split(':')
            host_redis_metadata = os.getenv('D4_REDIS_METADATA_HOST', d4_server)
            port_redis_metadata = int(os.getenv('D4_REDIS_METADATA_PORT', d4_port))
            self.r_d4 = redis.Redis(host=host_redis_metadata, port=port_redis_metadata, db=2)
        else:
            self.logger.info("Starting local analyzer")
            self.update_queue()
            self.cap_list = []
            self.process_local()
            time.sleep(15)
            c = self.update_queue()
            if c == 0:
                self.enqueue_caps(cap_list=list_caps('scanning', self.r))
                self.r.delete('scanning')
                print('[-] Process remaining unfinished caps.')
                self.process_local()

    def enqueue_caps(self, cap_list: list):
        p = self.r.pipeline()
        for cap in cap_list:
            p.rpush(self.queue, cap)
        p.execute()

    def update_queue(self):
        """
        Each parser instance is given a list of days, and thus a list of caps to parse.
        This method lets the parser confront his list of caps with the caps in his queue.
        """
        remaining_caps = list_caps(self.queue, self.r)
        current_caps = list_caps('scanning', self.r)
        parsed_caps = list_caps('scanned', self.r)
        caps_to_add = []
        if remaining_caps:
            print('[*] Queue already populated.')
            if self.cap_list:
                for cap in self.cap_list:
                    if cap not in remaining_caps and cap not in parsed_caps and cap not in current_caps:
                        caps_to_add.append(cap)
            if not caps_to_add:
                print('[*] Already up to date.')
                return 1
            print('[o] Queue updated.')
        else:
            if self.cap_list:
                print('[*] No caps, initializing...')
                caps_to_add = self.cap_list
            elif current_caps:
                return 0
        self.enqueue_caps(caps_to_add)
        return 2

    def parse_cap(self, cap):
        """
        Dissects the cap file to extract info.
        """
        if cap is None:
            print('[X] No caps to parse!')
            return 0

        print('[*] Started parsing...')

        pipeline = self.r.pipeline()
        for packet in cap:
            ip_layer = packet.ip
            icmp_layer = packet.icmp

            icmp_type = str(icmp_layer.type)
            icmp_code = str(icmp_layer.code)
            protocol = get_protocol(packet)
            checksum_status = check_icmp_checksum(packet.icmp_raw.value)

            if protocol == '1 : icmp':
                payload = get_icmp_payload(packet)
                pipeline.zadd('data', {'total': 1}, incr=True)
                pipeline.zadd('data', {payload: 1}, incr=True)

            if 'ip_src' in packet.icmp.field_names:
                ip = get_icmp_ip(packet)
                pipeline.hset('sources', ip, ip_layer.src)

            pipeline.hincrby('icmp', 'total')
            if icmp_type in unassigned_icmp_types:
                pipeline.hincrby('icmp', icmp_type + ' (unassigned)')
            elif icmp_type in deprecated_icmp_types:
                pipeline.hincrby('icmp', icmp_type + ' (deprecated)')
            else:
                pipeline.hincrby('icmp', icmp_type)

            pipeline.hincrby('checksum', 'total')
            pipeline.hincrby('checksum', checksum_status)

            entry = str(get_src_port(packet)) + ':' + protocol + ':' + icmp_type + ':' + icmp_code
            # pipeline.zadd(source_ip, {entry: 1}, incr=True)

            pipeline.zadd('protocols', {protocol: 1}, incr=True)
            # pipeline.zadd(protocol, {source_ip: 1}, incr=True)

            dst_port = get_dst_port(packet)
            if int(dst_port) == 80 | int(dst_port) == 443:
                pass
                # TODO
        pipeline.execute()

        self.logger.debug('Pipelining to redis.')
        return 0

    def pop_cap(self):
        absolute_path = None
        if not self.dataset:
            absolute_path = self.r_d4.rpop(self.queue)
        else:
            absolute_path = self.r.rpop('to_scan')
        return get_cap(absolute_path)

    def process_d4(self):
        while True:
            d4_cap = self.pop_cap()
            if d4_cap is None:
                time.sleep(1)
                continue
            self.logger.debug('Parsing file {}'.format(d4_cap.input_filename))
            self.parse_cap(d4_cap)
            d4_cap.close()

    def process_local(self):
        while self.r.llen(self.queue) != 0:
            cap = self.pop_cap()
            self.r.rpush('scanning', cap.input_filename)
            self.parse_cap(cap)
            self.r.lrem('scanning', 0, cap.input_filename)
            self.r.rpush('scanned', cap.input_filename)
            cap.close()
