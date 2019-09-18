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
    unassigned_icmp_types, deprecated_icmp_types, get_src_port, get_dst_port


class Analyzer:
    """
    Defines a parser to make bulk statistics on a large dataset of network captures.
    """

    def __init__(self):
        config = configparser.RawConfigParser()
        config.read('../etc/analyzer.conf')

        self.uuid = config.get('global', 'my-uuid')
        self.queue = "analyzer:1:{}".format(self.uuid)
        logging_level = config.get('global', 'logging-level')
        self.logger = logging.getLogger('')
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

        self.logger.info("Starting and using FIFO {} from D4 server".format(self.queue))

        analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
        analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6400))
        self.r = redis.Redis(host=analyzer_redis_host, port=analyzer_redis_port)

        d4_server, d4_port = config.get('global', 'd4-server').split(':')
        host_redis_metadata = os.getenv('D4_REDIS_METADATA_HOST', d4_server)
        port_redis_metadata = int(os.getenv('D4_REDIS_METADATA_PORT', d4_port))
        self.r_d4 = redis.Redis(host=host_redis_metadata, port=port_redis_metadata, db=2)

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
        absolute_path = self.r_d4.rpop(self.queue)
        return get_cap(absolute_path)

    def process(self):
        while True:
            d4_cap = self.pop_cap()
            if d4_cap is None:
                time.sleep(1)
                continue
            self.logger.debug('Parsing file {}'.format(d4_cap.input_filename))
            print('[*] Current cap file: {}'.format(d4_cap.input_filename[-15:]))
            self.parse_cap(d4_cap)
            d4_cap.close()
