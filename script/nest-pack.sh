#!/bin/bash

# check apakah di command ada "nest", kalau belum ada di install
if ! command -v nest &> /dev/null; then
    echo "nest not found, installing..."
    bun add -g @nestjs/cli
fi

# argument 1 adalah nama project
nest new $1
