#!/bin/bash
# description: quick installation ubuntu on termux with auto setup bashrc
# example: curl -fsSL https://init.jefripunza.com/termux-to-ubuntu.sh -o termux-to-ubuntu.sh && bash termux-to-ubuntu.sh

set -e # Exit immediately if a command exits with a non-zero status
## $1 could be empty, so we need to disable this check
#set -u # Treat unset variables as an error and exit
set -o pipefail # Cause a pipeline to return the status of the last command that exited with a non-zero status

DATE=$(date +"%Y%m%d-%H%M%S")
CURRENT_USER=$USER
rm -rf termux-to-ubuntu.sh

### ========================================================================== ###
###                               INITIALIZATION                               ###
### ========================================================================== ###

pkg update && pkg upgrade -y
pkg install python -y
pkg install proot-distro -y

proot-distro install ubuntu

echo 'alias ubuntu="proot-distro login ubuntu"' >> ~/.bashrc
source ~/.bashrc

echo '
# Auto-login to Ubuntu on Termux startup
if [ -z "$PROOT_DISTRIBUTION" ]; then
  exec proot-distro login ubuntu
fi
' >> ~/.bashrc

echo 'Success install ubuntu on termux'
