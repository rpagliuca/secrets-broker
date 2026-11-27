# Shared by the client helpers: settings and the client token.
# shellcheck shell=sh
cfg=${SECRETS_BROKER_CLIENT_ENV:-$HOME/.config/secrets-broker/client.env}
# shellcheck disable=SC1090
[ -r "$cfg" ] && . "$cfg"
SB_TOKEN_VAR=${SB_TOKEN_VAR:-SECRETS_BROKER_TOKEN}
SB_PROXY=${SB_PROXY:-127.0.0.1:8471}
SB_SSH_PORT=${SB_SSH_PORT:-8472}
SB_RUNTIME=${SB_RUNTIME:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/secrets-broker}
SB_BIN=${SB_BIN:-secrets-broker}
SB_GITHUB_LEVELS=${SB_GITHUB_LEVELS:-workflows write read}
eval "SB_TOKEN=\${$SB_TOKEN_VAR:-}"
