#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -e "${DIR}/.venv/bin/python" ]; then
  ENV_PY="${DIR}/.venv/bin/python"
else
  echo "Please make sure you ran install.sh first."
  exit 1
fi

if [ ! -d "${DIR}/db" ]; then
  mkdir db
fi

screen -dmS "ipa"
sleep 0.1

screen -S "ipa" -X screen -t "ipa-redis" bash -c "(redis-server ${DIR}/etc/redis.conf); read x;"
screen -S "ipa" -X screen -t "ipa-d4" bash -c "(cd bin; ${ENV_PY} ./run_ipa.py; read x;)"

exit 0