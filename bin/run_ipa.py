#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# IPA Launcher
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

from lib.analyzer import Analyzer

import argparse


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='D4-IPA')
    parser.add_argument('-p', '--path', type=int, nargs=1, help='Path of local dataset.')

    dataset = None

    args = parser.parse_args()
    if args.path:
        dataset = args.path[0]

    ipa = Analyzer(dataset_path=dataset)
