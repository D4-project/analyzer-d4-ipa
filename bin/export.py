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


analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6405))
r = redis.Redis(host=analyzer_redis_host, port=analyzer_redis_port)


def export_icmp_types():
    res = mds.table_row(['ICMP Type', 'Count'], [10, 10]) + '\n'
    res += '| :----- | -----: |\n'
    redis_dict = r.hgetall('icmp')
    for key in redis_dict:
        res += mds.table_row([key.decode(), redis_dict[key].decode()], [10, 10]) + '\n'
    return res


if __name__ == "__main__":
    export_icmp_types()
