# ICMP Passive Analyzer - D4 IPA

Reads a pcap file and analyze icmp packets to detect potential DDoS attacks 
(guaranteed gluten free)

## Installation
**REQUIREMENTS**: 
- This analyzer requires [pipenv](https://pipenv.readthedocs.io/en/latest/) and [redis 5.0](https://redis.io) or above.
- You need at least python3.6 or later to run this.

**SETUP**:\
First, you need to install pipenv:
```shell script
pip install pipenv
```
Then clone redis where you want it installed:
```shell script
git clone https://github.com/antirez/redis.git
cd redis
git checkout 5.0
make
cd ..
```

You can finally clone this repo on your machine and simply setup the virtual environment with pipenv like so:
```shell script
git clone https://github.com/D4-project/analyzer-d4-ipa.git
cd analyzer-d4-ipa
pipenv install
```