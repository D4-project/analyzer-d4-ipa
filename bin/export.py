#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Markdown export module
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

import markdown_strings as mds
import redis
import os
import time

analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6405))
r = redis.Redis(host=analyzer_redis_host, port=analyzer_redis_port)

table_line = '| :--------------- | :--------------- |\n'
padding = [16, 16]


def init_export_dir(path: str):
    if not os.path.exists(path):
        os.mkdir(path)


def export_icmp_types():
    res = mds.table_row(['ICMP Type', 'Count'], padding) + '\n' + table_line
    redis_dict = r.hgetall('icmp')
    for key in redis_dict:
        res += mds.table_row([key.decode(), redis_dict[key].decode()], padding) + '\n'
    return res


def export_protocols():
    res = mds.table_row(['Protocol', 'Count'], padding) + '\n' + table_line
    redis_list = r.zrange('protocols', 0, -1, withscores=True)
    for item in redis_list:
        res += mds.table_row([item[0].decode(), int(item[1])], padding) + '\n'
    return res


if __name__ == "__main__":
    pwd = os.getcwd() + '/exports/'
    init_export_dir(pwd)
    with open(pwd + str(time.time())[:10] + '-export.md', 'w') as exp_file:
        exp_file.write(export_icmp_types() + '\n')
        exp_file.write(export_protocols() + '\n')
