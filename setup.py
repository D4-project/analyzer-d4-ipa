#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import setup


setup(
    name='ipa',
    version='0.1',
    author='Romain Kieffer',
    author_email='romain.kieffer@telecom-sudparis.eu',
    maintainer='Romain Kieffer',
    url='https://github.com/D4-project/analyzer-d4-ipa',
    description='Pcap icmp parser focused on DDoS detection',
    packages=['lib'],
    scripts=['bin/run_ipa.py', 'bin/export.py'],
    include_package_data=True,
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
    ],
)
