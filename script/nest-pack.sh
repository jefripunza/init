#!/bin/bash
# example: curl -fsSL https://init.jefripunza.com/nest-pack.sh | bash -s -- my-project-name

set -e # Exit immediately if a command exits with a non-zero status
## $1 could be empty, so we need to disable this check
#set -u # Treat unset variables as an error and exit
set -o pipefail # Cause a pipeline to return the status of the last command that exited with a non-zero status

DATE=$(date +"%Y%m%d-%H%M%S")
OS_TYPE=$(grep -w "ID" /etc/os-release | cut -d "=" -f 2 | tr -d '"')
CURRENT_USER=$USER

# check apakah di command ada "nest", kalau belum ada di install
if ! command -v nest &> /dev/null; then
    echo "nest not found, installing..."
    bun add -g @nestjs/cli
fi

if [ -z "$1" ]; then
    echo "Please provide a project name"
    exit 1
fi
nest new $1
