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

## Usage
#### Start the redis server
Don't forget to set the DB directory in the redis.conf configuration. By default, the redis for IPA is running on TCP port 6405.
```shell script
../redis/src/redis-server ./etc/redis.conf
```

#### Configure and start the D4 analyzer
```shell script
cd ./etc
cp analyzer.conf.sample analyzer.conf
```
Edit analyzer.conf to match the UUID of the analyzer queue from your D4 server.
```shell script
[global]
my-uuid = 6072e072-bfaa-4395-9bb1-cdb3b470d715
d4-server = 127.0.0.1:6380
# INFO|DEBUG
logging-level = INFO
```

#### Start the analyzer
```shell script
cd ../bin
python3 run_ipa.py
```

If you have local pcaps stored in a dataset that you want to analyze, use -p argument and specify the absolute path of the dataset root folder.
```shell script
python3 run_ipa.py -p /absolute/path/to/dataset/root
```
