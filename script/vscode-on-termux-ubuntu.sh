#!/bin/bash
# description: quick installation ubuntu on termux with auto setup bashrc
# example: curl -fsSL https://init.jefripunza.com/vscode-on-termux-ubuntu.sh -o vscode-on-termux-ubuntu.sh && bash vscode-on-termux-ubuntu.sh

set -e # Exit immediately if a command exits with a non-zero status
## $1 could be empty, so we need to disable this check
#set -u # Treat unset variables as an error and exit
set -o pipefail # Cause a pipeline to return the status of the last command that exited with a non-zero status

DATE=$(date +"%Y%m%d-%H%M%S")
CURRENT_USER=$USER
rm -rf vscode-on-termux-ubuntu.sh

new_password=$1

### ========================================================================== ###
###                                  PROCESS                                   ###
### ========================================================================== ###

apt-get update && apt-get upgrade -y
apt-get install sudo nano python3 curl wget -y

python --version

curl -fsSL https://code-server.dev/install.sh | sh

code-server --version

echo '
# Mulai code-server otomatis hanya jika port 8080 belum respons
if curl -sSf http://127.0.0.1:8080 >/dev/null 2>&1; then
  echo "✅ code-server already running"
else
  cat /root/.config/code-server/config.yaml
  code-server --bind-addr 0.0.0.0:8080 &
  echo "🚀 code-server started"
fi
' >> ~/.bashrc

cat <<EOF > /root/.config/code-server/config.yaml
bind-addr: 0.0.0.0:8080
auth: password
password: $project_name
cert: false
EOF
