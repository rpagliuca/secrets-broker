# Client helpers

Small scripts for clients (agents) of the broker. Each reads, when present,
`$SECRETS_BROKER_CLIENT_ENV` (default `~/.config/secrets-broker/client.env`),
a shell file with these settings:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SB_TOKEN_VAR` | `SECRETS_BROKER_TOKEN` | environment variable holding the client token |
| `SB_PROXY` | `127.0.0.1:8471` | the broker's HTTP proxy |
| `SB_SSH_PORT` | `8472` | the broker's SSH proxy port |
| `SB_RUNTIME` | `$XDG_RUNTIME_DIR/secrets-broker` | directory with `ca.pem` and `ssh_known_hosts` |
| `SB_BIN` | `secrets-broker` | the command line |
| `SB_GITHUB_OWNERS` | | `owner=prefix ...`: a repository's names are `prefix/<repo>/<level>` |
| `SB_GITHUB_LEVELS` | `workflows write read` | the levels, highest first |
| `SB_GITHUB_ALL_REPOS` | | a credential for calls with no repository (`gh api user`) |
| `SB_GIT_SSH_TARGETS` | | `github.com=name bitbucket.org=name`: git over SSH through these targets |

- `secrets-broker-ssh TARGET [ssh options] [command]`: SSH to a target.
- `secrets-broker-askpass`: hands the token to ssh as the proxy password.
- `git-remote-broker`: git transport for `broker::https://github.com/OWNER/REPO`
  (with `url.broker::https://github.com/.insteadOf https://github.com/`), using
  the repository's name at the highest level granted.
- `secrets-broker-git-ssh`: `core.sshCommand` that sends git over SSH through
  the broker for the hosts of `SB_GIT_SSH_TARGETS`.
- `gh`: put it before the real `gh` (renamed `gh.real`): the GitHub API goes
  through the broker with the repository's name. Without a grant it fails
  with how to ask, instead of running `gh`.
- `secrets-broker-github-name OWNER/REPO`: the highest name granted, or nothing.
