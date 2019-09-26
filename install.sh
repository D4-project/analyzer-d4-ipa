#!/bin/bash

set -e
set -x

export PIPENV_VENV_IN_PROJECT=1

if [ -z "$VIRTUAL_ENV" ]; then
    pipenv install
    export IPA_HOME=$(pwd)
fi

