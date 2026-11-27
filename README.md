# secrets-broker

A small HTTPS proxy that lets an untrusted client, such as an AI agent, use an
API credential without ever holding it. It can also proxy SSH, with the same
rule: the client reaches the machine, the private key stays in the broker.

The client sends its request through the broker with a token of its own. The
broker checks who is asking and where the request is going, and adds the real
`Authorization` header on the way out. The credential exists only in the
memory of the broker, which runs under a different user and is opened at each
boot with a key that can be kept on a hardware token on another machine.

Status: first version. It has not been audited. Read the limits below before
relying on it.

## How it works

```
 client (untrusted)                 broker (own user, secrets in RAM)            service
 ------------------                 ---------------------------------            -------
 CONNECT api.example.com:443   -->  1. authenticate the client token
 Proxy-Authorization: <token>       2. host configured? client group allowed?
                                    3. secret unsealed and bound to this host?
 TLS (broker CA)               -->  4. SNI must equal the CONNECT host
 GET /v1/items                 -->  5. Host header must equal the CONNECT host
 Authorization: <anything>          6. replace Authorization with the real one  -->  TLS, verified
                               <--  7. scan the response for the credential     <--
```

1. The client talks to the broker as an HTTPS proxy and authenticates with
   `Proxy-Authorization`. The token identifies the client and its groups.
2. Each credential is bound to exact host names and to the groups allowed to
   use it. Any other host is refused at `CONNECT`; nothing is tunnelled.
3. The broker terminates TLS with a certificate authority created at start-up.
   The CA key never leaves memory, and the CA certificate carries name
   constraints limited to the configured hosts.
4. The request is sent to `https://<host>`, with normal certificate
   verification, by the broker itself. The client never chooses the address.
5. The broker never follows redirects. A `3xx` goes back to the client, and
   the next request is judged on its own: another host gets no credential.

## What is enforced

Each item has a test in `broker/proxy_test.go` or `broker/scopes_test.go`.

| Attack | Result |
| --- | --- |
| Send the request to a host the attacker controls | `403` at `CONNECT`; nothing leaves the broker |
| Open a tunnel to the right host and use another `Host` header | `421`; nothing leaves the broker |
| Open a tunnel to the right host and present another SNI | TLS handshake fails |
| Make the service redirect to another host | the `3xx` is returned as is; the follow-up is refused |
| Write a placeholder in the body or URL hoping it is replaced by the secret | nothing is ever replaced; only the `Authorization` header is set |
| Use a credential of another group | `403` |
| Use a credential without a grant, or after the grant expired (with `approval`) | `403`, also inside an open tunnel |
| Edit the configuration to point a secret at a new host | `403`: the host list is stored inside the encrypted secret |
| Make the service echo the request headers (`TRACE`, debug endpoints) | `TRACE` is refused; a response containing the credential is cut |
| Use a grant of a scope on another path, another method, or with `..`, `;` or an encoded `/` | `403`; nothing leaves the broker |
| Ask the service for an encoding the broker cannot read | the broker negotiates the encoding itself; an unreadable response is refused |

## What is not covered

- **Misuse inside the rules.** A client that is allowed to use a credential
  can do anything that credential can do on that host, including reading data
  and sending it elsewhere by other means. Use credentials with the smallest
  scope the service offers, `methods` for read-only access, and `scopes`
  to narrow a grant to some paths (see "Scopes").
- **Credentials that create credentials.** If the service lets a token create
  another token or key, the client can ask for one and read it in the
  response. (The master of a `cloudflare_token` credential is never sent on
  a client's request; the tokens it issues must not manage tokens.)
- **Root, or the broker's own user.** Memory locking and the non-dumpable flag
  stop other processes of the same user and keep secrets out of swap and core
  dumps. They do nothing against root. If the client can become root on the
  machine (membership of the `docker` group counts), the broker protects
  nothing.
- **Transformed echoes.** The response scan looks for the secret and for the
  exact header value. A service that returns the credential reversed or
  re-encoded is not detected.
- Protocols other than HTTPS on port 443, HTTP upgrades (WebSocket) and
  client certificates are not supported.

## Quick start

Requires Go 1.26 or newer, [`age`](https://age-encryption.org) and `jq`.

```sh
make build

# 1. Vault key. For a first try, a plain key file (see "Hardware key" below
#    for the real setup). Note the public key it prints.
age-keygen -o vault.key

# 2. One secret, bound to its host. The value is read from standard input.
mkdir secrets
printf '%s' "$API_TOKEN" \
  | jq -Rc '{value: ., hosts: ["api.example.com"]}' \
  | age -r age1...vault-public-key... -o secrets/example-api.age

# 3. A token for the client. Put the sha256 in tokens.json.
./secrets-broker token

# 4. Configuration: see examples/config.json and examples/tokens.json.
./secrets-broker serve -config config.json

# 5. Unseal.
./secrets-broker unseal -socket control.sock < vault.key

# 6. Use it.
curl --proxy "http://agent:$CLIENT_TOKEN@127.0.0.1:8471" \
     --cacert ca.pem https://api.example.com/v1/items
```

The client may send any `Authorization` header, or none; it is replaced.

Most tools accept a proxy and a CA bundle through the environment
(`HTTPS_PROXY`, and `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` or
`NODE_EXTRA_CA_CERTS`). Set them for the specific command or tool: the broker
refuses every host that has no credential, so it cannot be a general-purpose
proxy.

## Configuration

`config.json` holds no secret and is meant to be kept in version control.
Unknown fields are rejected.

| Field | Meaning |
| --- | --- |
| `listen` | Proxy address, `host:port`, with an explicit host (use a loopback address) |
| `control_socket` | Unix socket for `unseal`, `seal` and `status`; created with mode `0660` |
| `ca_cert_file` | Where the CA certificate is written at start-up (a new CA at every start) |
| `secrets_dir` | Directory of `<name>.age` files |
| `tokens_file` | Client tokens, by SHA-256 |
| `approval` | Optional. Makes every use depend on a time-limited grant (see "Approval") |
| `credentials[].name` | Name in the audit log, and the secret name unless `secret` is set |
| `credentials[].hosts` | Exact, lower-case host names; no wildcard, no port |
| `credentials[].groups` | Client groups allowed to use the credential |
| `credentials[].scheme` | `bearer`, `basic` with `username`, `oauth2` with `token_url`, `github_app` with `github_app`, or `cloudflare_token` with `cloudflare` |
| `credentials[].methods` | Optional list of allowed HTTP methods |
| `credentials[].upstream` | Optional. Where the requests really go, as `http://host:port` or `https://host:port`, instead of `https://<host>`: a service on another port, or without TLS on a private network that is already encrypted. The client still talks HTTPS to the broker under the single name in `hosts`. With `http://` the credential crosses that network in clear text |
| `credentials[].token_url` | For scheme `oauth2` (see "OAuth") |
| `credentials[].github_app` | For scheme `github_app` (see "GitHub App") |
| `credentials[].cloudflare` | For scheme `cloudflare_token` (see "Cloudflare tokens issued per client") |
| `credentials[].scopes` | Optional. Narrower names, each allowing some methods on some paths (see "Scopes") |
| `credentials[].default` | The one used when several credentials serve a host and the client names none |
| `services` | Optional. Clients without a person, each with a fixed list (see "Services") |
| `ssh` | Optional. Starts the SSH proxy (see "SSH") |
| `aws` | Optional. Temporary AWS credentials (see "Temporary AWS credentials") |
| `commands`, `commands_dir` | Optional. Programs run for clients (see "Commands") |

A host and group pair is served by one credential, or by several with one
marked as the default (see "Several credentials for one host"): there is
never a silent choice of which secret to send.

`SIGHUP` re-reads the secrets directory (with the key already in memory), the
tokens file and the configuration: credentials and SSH targets are replaced
without a restart, so the broker stays unsealed. Hosts already configured keep
their CA, so a client that read `ca_cert_file` before the reload keeps
working; new hosts get one more CA, appended to the file, which a
long-running client only trusts after reading the file again. Tunnels opened
before the reload must be opened again. Listen addresses, the
control socket, the approval settings and adding or removing the `ssh` block
only change with a restart, and a restart leaves the broker sealed.

Whoever can write the configuration file and signal the process can therefore
change the policy without the vault key. Keep the file owned by an account
the clients cannot use.

## Approval

With an `approval` block, belonging to the right group is not enough: each
client needs a grant for each credential, given by a person, for a limited
time.

```json
"approval": { "durations": ["1h", "4h", "12h"], "request_ttl": "10m", "cooldown": "10m" }
```

1. The first request of a client for a credential is refused with `403` and
   creates a waiting request. The client retries later.
2. The approver sees the client id and name (from the authenticator), the
   credential and its hosts (from the configuration). The client may add
   a reason of at most 200 characters for each credential: that is the only
   text of its own in the request, kept apart so that it is never shown as
   the broker's word.
3. The approver grants it for one of the durations, or refuses it. A grant
   covers that client and that credential only, and is checked on every
   request, so it also ends inside an open tunnel.
4. After a refusal the client cannot ask again for that credential during
   `cooldown`. A request nobody answered within `request_ttl` just expires:
   it is not a refusal, and the client may ask again at once. At most 20
   requests wait at a time.

Grants live in memory: a restart forgets them. Requests are answered through
the control socket:

```sh
secrets-broker pending
secrets-broker approve 3f9a1c22 1h
secrets-broker approve 3f9a1c22 1h -only name-a,name-b   # part of it; the rest is refused
secrets-broker deny 3f9a1c22
secrets-broker deny 3f9a1c22 ask for the repository scope   # the client reads the text
secrets-broker approve 3f9a1c22 1h -only name-a -why too broad for this task
secrets-broker grants
secrets-broker revoke agent-1      # or: revoke all
secrets-broker blocked             # clients kept from asking again after a refusal
secrets-broker unblock agent-1     # or: unblock all; lets them ask again, grants nothing
```

The text after `deny ID`, or after `-why`, goes with the cooldown of the
refused credentials: the client reads it in the refusal of its next request
(`not approved (the approver said: "..."); a new request is accepted after
...`), and the audit log records it. It is cut to 300 bytes.

When the broker stops, the waiting requests end and the notifier takes the
questions off the approver's devices (up to 15 seconds); a request made
while the store is sealed is delivered after the unseal.

A deployment can deliver the request somewhere else, such as a phone, by
implementing `broker.Notifier` and calling `Grants.Decide` with the answer.
For the approval to count as a second factor, the answer must reach the
broker through a path the clients cannot write to.

The `pushward` package is one such `Notifier`, for
[PushWard](https://pushward.app): the broker sends a notification with one
button per duration plus a refusal, each requiring the phone to be unlocked,
and reads the answer from the PushWard API. The broker only makes outbound
requests, and the integration key is a secret of its own store, bound to
`api.pushward.app`. The notification text passes through PushWard's servers.

## SSH

With an `ssh` block, the broker also listens for SSH. The client connects to
the broker, gives the name of a target as the user and its token as the
password, and the broker opens the connection to the target with a private
key from its store and relays the session.

```json
"ssh": {
  "listen": "127.0.0.1:8472",
  "known_hosts_file": "/run/secrets-broker/ssh_known_hosts",
  "targets": [
    {
      "name": "web",
      "address": "web.example.com:22",
      "user": "deploy",
      "host_keys": ["ssh-ed25519 AAAA..."],
      "groups": ["team-a"]
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `listen` | Address of the SSH proxy, with an explicit host |
| `known_hosts_file` | Where the host key of the proxy is written at start-up (a new key at every start) |
| `targets[].name` | What the client gives as the SSH user, and the secret name unless `secret` is set |
| `targets[].address` | `host:port` of the target |
| `targets[].user` | Account on the target |
| `targets[].host_keys` | Accepted host keys of the target. Required: there is no trust on first use |
| `targets[].groups` | Client groups allowed to use the target |
| `targets[].jump` | Optional. Another target to connect through |
| `targets[].via` | Optional, not with `jump`. A command (such as a VPN) to reach `address` through: one of its `forwards` must be `address`. The broker starts the command for the client when needed, kept up by this target's grant, and connects through its socket; the client never holds the key |
| `targets[].forward` | Optional. `host:port` destinations allowed for `ssh -L` |

The secret of a target is its private key in OpenSSH format, without
passphrase, bound to the host part of `address`:

```sh
ssh-keygen -t ed25519 -N '' -C broker-web -f /dev/shm/k    # on the machine that holds the vault key
jq -Rsc '{value: ., hosts: ["web.example.com"]}' /dev/shm/k \
  | age -r "$VAULT_PUBLIC_KEY" -o secrets/web.age
cat /dev/shm/k.pub     # goes into authorized_keys of deploy@web.example.com
shred -u /dev/shm/k
```

The client uses the stock `ssh` command. The token is handed over by an
askpass program, so it is never typed and never on a command line:

```sh
cat > askpass <<'SH'
#!/bin/sh
printf '%s\n' "$BROKER_TOKEN"
SH
chmod +x askpass

SSH_ASKPASS=$PWD/askpass SSH_ASKPASS_REQUIRE=force \
  ssh -p 8472 -o UserKnownHostsFile=/run/secrets-broker/ssh_known_hosts \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      web@127.0.0.1 uptime
```

`scp` and `sftp` work the same way. What is enforced:

- The private key never reaches the client, and signs nothing until the host
  key of the target matched one of the configured keys.
- A target of another group gets the same answer as a target that does not
  exist.
- With `approval`, a target needs a grant like a credential does (it is named
  `ssh:<target>` in requests and grants). The first connection is refused
  with the request id; the target is not contacted before the grant.
- Open connections are checked again every few seconds. When the grant ends
  or is revoked, the token stops being valid or the broker is sealed, the
  connection is closed.
- A jump target is used by the broker on the way to the final one; the client
  needs no access to it and gets none.
- Agent forwarding, X11 forwarding and remote port forwarding (`ssh -R`) are
  refused. Local forwarding (`ssh -L`) only reaches the destinations listed
  in `forward`.
- The audit log has one event per connection, per command (`ssh-exec`, with
  the command line, cut at 512 bytes), per subsystem and per interactive
  shell. What is typed inside an interactive shell is not logged.

A grant covers the whole account on the target: the broker does not restrict
which commands run. To restrict them, use `command=` in `authorized_keys` on
the target. Do not put secrets on command lines sent through the proxy: they
end up in the audit log.

## Temporary AWS credentials

AWS requests are signed, not sent with a header, so the broker does not proxy
them. It holds a long-term access key and hands out sessions that expire.

```json
"aws": [
  {"name": "prod", "groups": ["team-a"], "region": "us-east-1", "max_duration": "1h"}
]
```

The secret is `ACCESS_KEY_ID:SECRET_ACCESS_KEY`, bound to the STS host of the
region (`sts.us-east-1.amazonaws.com`). `GET /aws/prod` with
`Authorization: Bearer <token>` answers in the `credential_process` format,
after the same checks as a credential (group, grant named `aws:prod`). With
`role_arn` the broker calls `AssumeRole`; without it, `GetSessionToken`.
With both `role_arn` and `mfa_serial` it opens a session of the user with the
one-time code (`GetSessionToken`) and assumes the role with that session, so
that a policy on the user denying what is done without MFA
(`aws:MultiFactorAuthPresent`) does not block the `AssumeRole`.

```ini
[profile prod]
credential_process = /usr/local/bin/secrets-broker aws-credentials -token-env BROKER_TOKEN prod
```

Unlike a proxied credential, the client holds what it receives until it
expires. The session lasts at most `max_duration` (default 1h) and ends with
the grant, but never lasts under 15 minutes, the shortest STS issues: a
revoked client keeps its session for up to that long.

For a role or a policy that requires MFA, add the device to the account:

```json
{"name": "audit", "groups": ["team-a"], "role_arn": "arn:aws:iam::123456789012:role/read-only",
 "mfa_serial": "arn:aws:iam::123456789012:mfa/key-1"}
```

Such an account needs approval. Its request cannot be granted from a
notification button, which has nowhere to type: the approver gives the
one-time code with the answer, `secrets-broker approve 3f9a1c22 1h
aws:audit=123456`. The broker opens the session with that code then and
there, hands it to the client while the grant lasts and cannot renew it: the
grant ends with the session (`max_duration`), and the client asks again.
A wrong or used code leaves the request waiting, and the answer carries what
STS said: it tells a wrong code from a wrong device serial.

## OAuth

With `"scheme": "oauth2"` and a `token_url`, the secret is
`{"client_id", "client_secret", "refresh_token"}`, bound to the API hosts and
to the host of `token_url`. The broker exchanges the refresh token for an
access token, keeps it in memory until it expires and sends it as `Bearer`.
The client holds neither token; give it a placeholder.

## GitHub App

A personal access token reaches every repository of its account. A GitHub
App can do better: the broker holds the private key of the app and, for each
use, asks GitHub for an installation token limited to one repository and to
the permissions of the credential. The token lasts one hour, lives only in
the broker's memory and is renewed before it expires; the client holds
neither the key nor the token, and what the token reaches is enforced by
GitHub itself.

```json
{
  "name": "team/github/{repo}/write",
  "secret": "github-app",
  "hosts": ["api.github.com", "github.com"],
  "groups": ["team-a"],
  "scheme": "github_app",
  "github_app": {
    "app_id": "123456",
    "installation_id": 7890123,
    "permissions": {"contents": "write", "pull_requests": "write", "metadata": "read"}
  }
}
```

`{repo}` stands for any repository: the client asks for
`team/github/secrets-broker/write`, and the request, the grant, the audit log
and the token are for that repository alone. A name with `{repo}` serves only
when the client names it (as the proxy user, or in `request`); it is never a
default. Use one credential per level (read, write, workflows), all with the
same secret. Without `{repo}`, `repositories` lists the repositories of the
token, and without either the token reaches every repository of the
installation.

The secret is the private key file GitHub hands out (`.pem`), as it is,
bound to the API host and to the git host. Requests to `api.github.com`
carry `Bearer <token>`; requests to any other host of the credential, such
as `github.com` for git over HTTPS, carry `Basic x-access-token:<token>`.
For GitHub Enterprise, set `api_host`.

Permissions are those of the GitHub API (`contents`, `pull_requests`,
`issues`, `workflows`, ...), each `read` or `write`, at most what the app was
installed with. Note that `contents: write` with `pull_requests: write` also
merges pull requests: only branch protection on the repository stops that.

## Cloudflare tokens issued per client

Cloudflare lets a token create other tokens, each with its own policies and
expiry. With scheme `cloudflare_token`, the secret is such a token (the
master), and it is never sent on a client's request. For each client, on its
first request after the grant, the broker creates a token limited to the
policies of the credential, which expires when the grant ends (or after
`max_duration`, default 1h, renewed while the grant lasts), and sends that
one as `Bearer`. Neither token reaches the client.

```json
{
  "name": "team/cloudflare/example.com/dns-edit",
  "secret": "cloudflare-master",
  "hosts": ["api.cloudflare.com"],
  "groups": ["team-a"],
  "scheme": "cloudflare_token",
  "cloudflare": {
    "account_id": "<account id>",
    "policies": [
      {"effect": "allow",
       "resources": {"com.cloudflare.api.account.zone.<zone id>": "*"},
       "permission_groups": [{"id": "<id of Zone Read>"}, {"id": "<id of DNS Write>"}]}
    ],
    "request_ip": ["203.0.113.0/24"]
  }
}
```

`policies` are written as the Cloudflare API takes them, with the ids of the
permission groups (`GET /client/v4/accounts/<id>/tokens/permission_groups`
lists them). Several credentials may share one master, each with its own
scope: the approver grants the small one by its name. `request_ip` is
optional and limits the issued token to those addresses, as Cloudflare sees
them.

With `account_id`, the issued tokens are owned by the account and the master
needs "Account API Tokens Write" on that account only. Without it, they are
user tokens and the master needs "API Tokens Write", which reaches every
account of the user. Cloudflare never lets an issued token exceed its
creator. Do not put a permission to manage tokens in the policies: the client
could then create a token and read it in the response.

Every minute the broker deletes the tokens whose grant ended or was revoked,
whose credential changed or left the configuration (after `SIGHUP`), or that
expired; when it stops, it deletes them all. Each creation and deletion is
an event in the audit log, with the id of the token. A sealed broker no
longer holds the master and cannot delete: what it issued ends at its expiry.
On Cloudflare the tokens are named `secrets-broker <credential> <client>
<time>`.

## SQL, one approved statement at a time

A database entry lets a client run SQL it wrote, after the approver read it.
The client never gets a connection or a password:

```json
"databases": [
  {"name": "prod-reader", "groups": ["team-a"], "address": "db.example.com:3306",
   "user": "reader", "aws": "prod-db-role", "ca_file": "/etc/secrets-broker/rds-ca.pem",
   "write": false, "max_rows": 1000, "max_timeout": "5m"}
]
```

1. The client asks with the exact statement and the time it needs:
   `POST /requests {"credentials": ["sql:prod-reader"], "queries": {"sql:prod-reader": {"sql": "SELECT ...", "timeout": "30s"}}, "reasons": {...}}`.
2. The approver reads the statement (the notification only says it is on the
   broker) and approves it with the one-time code of the AWS account named in
   `aws`, which must have `mfa_serial`.
3. `POST /sql/sql:prod-reader` runs that statement once and ends the grant.
   The answer is JSON: `columns`, `rows` (text, `null` for NULL), `truncated`.

The broker signs in with an IAM authentication token (MySQL, TLS checked
against `ca_file`). Without `write`, the statement runs in a READ ONLY
transaction; `max_execution_time` and the context follow the approved
timeout, and at most `max_rows` rows come back. The statement is written to
the audit log; the result is not.

## Commands

For what is neither a header nor SSH, such as a VPN, the broker can run a
program for the client.

```json
"commands_dir": "/run/secrets-broker/commands",
"commands": [
  {
    "name": "vpn",
    "groups": ["team-a"],
    "files": [{"secret": "vpn-config", "name": "client.ovpn"}],
    "start": ["/usr/local/bin/vpn-up", "{dir}/client.ovpn"],
    "stop": ["/usr/local/bin/vpn-down"]
  }
]
```

`POST /commands/vpn/start` (with `Authorization: Bearer <token>`) checks the
group and the grant (`command:vpn`), writes each secret to a file under
`commands_dir/vpn` (mode 0600; `{dir}` in arguments and `env`), runs `start`
and returns its output with the secrets blanked. `POST /commands/vpn/stop`
runs `stop` and removes the files; `GET /commands/vpn` reports the state. The
broker stops the command by itself when the grant or the token of the client
ends, when it is sealed and when it shuts down. Each secret must be bound to
the host `command:vpn`.

What the command makes reachable can be kept behind the broker as well. With
`"forwards": {"10.0.0.5:5432": "db.sock"}`, the program listens on the Unix
socket `{dir}/db.sock` instead of a TCP port, and the client reaches it with
`ssh -L 5432:10.0.0.5:5432 vpn@broker` through the SSH proxy (the SSH user is
the command name). Only the client that started the command is let in, while
its grant lasts; a port open on the machine would serve every local process.

The program and its arguments come only from the configuration. They run as
the broker user, and whatever can read `commands_dir` or the process started
by `start` can read the secret: this mechanism protects less than the
proxies and is only as tight as the program it runs.

## Asking ahead

A client that knows what a task needs can ask for all of it at once, instead
of being refused at each first use:

```sh
secrets-broker access                               # what may be asked for, and what is held
secrets-broker request -for 4h issues-team-a ssh:web aws:prod
```

(`GET /grants` and `POST /requests` with `Authorization: Bearer <token>`;
both commands take `-token-env NAME`.) The approver gets one question with
every name and the suggested duration (the buttons keep their order); one
answer grants or refuses them all. Names are `credential`, `ssh:<target>`,
`aws:<account>` and `command:<name>`. The client names things and suggests a
duration. It may also say why it wants each name, as `NAME=WHY` (200
characters at most). That reason is the client's own, unverified text: it
is kept apart in the request (`secrets-broker pending json` shows it) and
the reference notifier leaves it out of the question.

By default the first use of a credential without a grant creates the
request. With `"explicit_only": true` in `approval`, a use without a grant is
just refused and nobody is notified: requests only come from the client
asking (see "Asking ahead"). Use it when clients run tools that touch a
service on their own (a status poller, a server that lists its resources at
start-up), which would otherwise cause requests nobody made.

With `"require_reason": true` in `approval`, a request is refused unless it
says why the client wants each credential (`NAME=WHY`, at least 10
characters each). It implies `explicit_only`, since a request born from a
use has no reason.

## Names that say what they give

The approver decides by the name. A plain name gets its kind in front
(`ssh:web`, `aws:prod`, `command:vpn`), which says how it is used but not
what it reaches. A name may instead be a path, and is then used whole, in
requests, grants, the log and the client's commands:

```json
{"name": "team/github/ssh/all-repositories", "secret": "ssh-deploy", "address": "github.com:22", "...": "..."}
```

Write the path so that its last part states the most the thing gives access
to if misused, not what it is meant for: `team/aws/prod/read-only`,
`team/github/api-token/every-repository-and-workflow`. A name that is a path
needs `secret`, because the secret store has flat names, and no two things
may share a name. In a proxy URL the slashes of the name are written `%2F`.

## Scopes

A service often has one token for everything the account reaches. A scope
is a narrower name for part of it: the same secret, on the same hosts, but
a grant of the scope allows only the requests that match its rules.

```json
{
  "name": "team/git-host/api-token/account-write", "secret": "git-host", "hosts": ["api.git.example"],
  "groups": ["team-a"], "scheme": "bearer",
  "scopes": [
    {"name": "team/git-host/repo/{repo}/read-and-comment", "rules": [
      {"methods": ["GET", "HEAD"], "paths": ["/2.0/repositories/team/{repo}/**"]},
      {"methods": ["POST"], "paths": ["/2.0/repositories/team/{repo}/pullrequests/*/comments"]}
    ]}
  ]
}
```

The client asks for `team/git-host/repo/web/read-and-comment` like any
other name, and the approver reads which repository it is. Once granted,
`GET /2.0/repositories/team/web/src/...` goes through and
`GET /2.0/repositories/team/other/...` or a merge is refused with `403`.
`GET /grants` lists the pattern; `POST /requests` takes instances of it,
several in one question.

- A **parameter** (`{repo}`) is a whole segment of the name, and its value
  follows the rules of a name (lower case, digits, `.`, `_`, `-`). In a path
  it may be part of a segment (`/issue/{project}-*`) and is compared without
  regard to case. Every parameter must restrict some path.
- In a **path pattern**, `*` is any text within one segment and `**`, as the
  last segment only, any number of further segments, none included. The
  query string is not looked at.
- A request is allowed when **any** scope the client holds on the
  credential allows it, so one tunnel (an MCP server, a CLI) serves several
  grants. A grant of the credential's own name still allows everything.
  Without either, the credential is asked for, as before.
- A scope may be named as the proxy user, to choose the credential when
  several serve a host.
- Paths the service might read otherwise than the broker are refused
  before any rule is tried: encoded `/`, `\`, `.` or `;`, a doubly encoded
  character, a `;` (path parameters, which some servers drop before
  routing), dot segments and empty segments.
- The audit log names the scope that allowed each request.

What a scope cannot do, because it only sees the method and the path:

- A **search** whose query is in the query string or in the body (a query
  language, a filter) reaches whatever the account reaches. Allow such
  endpoints only in scopes meant to read everything.
- An object addressed by an **id** that does not say where it belongs (a
  page id, a comment id) cannot be tied to a container by its path.
- The **response** is not filtered: what the service puts in it (links,
  summaries of related objects) reaches the client.

## Open credentials

Some things are meant for every client, and are still worth keeping in the
broker: the secret stays out of reach and each use is logged. List them in
`approval.open`, by the name used in grants:

```json
"approval": {"durations": ["1h", "4h"], "open": ["ssh:mirror", "packages"]}
```

Any authenticated client of the right group uses them at once, with no
request to the approver. Everything else still needs a grant.

## Services

A program that runs without a person (a timer, a daemon) cannot wait for an
approval. It gets a token of its own and a fixed list:

```json
"services": [
  {"id": "collector", "name": "Alert collector", "sha256": "<SHA-256 of its token>",
   "groups": ["team-a"], "credentials": ["aws:prod"]}
]
```

The service uses what is on its list at once, with no approval, and is
refused anything else; it cannot ask for more. It appears in the audit log
as `service:collector`. Removing it from the configuration (and reloading)
ends its access. The token is a secret of the service: keep it where only
the service reads it, such as an environment file with mode 0600. What it is
worth is the list, and only while the broker is unsealed: a service that
must work right after a reboot will wait for the unseal.

## Several credentials for one host

Two credentials may serve the same host for the same group when exactly one
is marked `"default": true`. The client picks one by giving its name as the
user name of the proxy (`http://<credential>:<token>@127.0.0.1:8471`); any
other user name gets the default. Each has its own grant.

## Secrets

Each secret is one age file whose plaintext is
`{"value": "...", "hosts": ["..."]}`. The files are encrypted to the vault's
public key, so secrets can be added from a machine that cannot decrypt them.
Encrypt to a second recipient as well if you want a recovery path.

The host list inside the file is checked on every request, in addition to the
configuration. To send a secret to a new host, someone who knows the secret
has to encrypt it again.

## Hardware key

The vault key does not need to exist in clear on any disk. With
[`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey), on the
machine that has the token:

```sh
# Once: create the vault key and store it encrypted to the hardware token.
# The vault public key is printed on the terminal; the private key only
# exists inside the pipe.
age-keygen | age -r age1yubikey1... -o vault-key.age

# At each boot of the broker: decrypt with the token and deliver over SSH.
age -d -i yubikey-identity.txt vault-key.age | ssh unseal@broker-host
```

On the broker host, the `unseal` account should be a dedicated user in the
group of the control socket, with a forced command in `authorized_keys`:

```
command="/usr/local/bin/secrets-broker unseal",restrict ssh-ed25519 AAAA...
```

Do not deliver the key through an account the clients can write to: a shell
profile or a replaced binary in that account would see the key.

## Deployment notes

- Run the broker under a user of its own. Clients must not be able to become
  that user or root.
- `mlockall` needs `LimitMEMLOCK=infinity` (or `CAP_IPC_LOCK`). With every
  page locked, the process uses about 150 MB of resident memory.
- Suggested systemd settings: `NoNewPrivileges=yes`, `ProtectSystem=strict`,
  `ProtectHome=yes`, `PrivateTmp=yes`, `LimitCORE=0`, `RuntimeDirectory=`
  for the socket and the CA certificate.
- The audit log goes to standard output, one JSON object per decision. It
  contains the client id, credential name, host, method, path and status,
  never a secret or a token.

## Using it as a library

The reference binary is a thin wrapper around three interfaces of the
`broker` package, which depends only on the standard library:

```go
type Store interface         { Get(name string) (Secret, error) }
type Authenticator interface { Authenticate(ctx context.Context, token string) (Principal, error) }
type Auditor interface       { Record(Event) }
type Notifier interface      { Notify(ctx context.Context, g *Grants, req Request) }
```

A deployment can keep `agestore` and replace the authenticator (for example
with the session tokens of whatever launches the agents), the auditor and the
notifier. The `cli` package gives such a binary the same command line:

```go
func main() {
	cli.Main(func(cfg *broker.Config, o *broker.Options) error {
		o.Auth = myAuthenticator{}
		o.Notifier = &pushward.Notifier{Store: o.Store, Secret: "pushward"}
		return nil
	})
}
```

## Not in this version

- Pass-through for hosts without a credential, and an egress allow-list.

## Development

```sh
make check   # gofmt, go vet, tests with the race detector, govulncheck
```

Dependencies are limited to the standard library, `filippo.io/age` and
`golang.org/x/crypto/ssh`.

## License

MIT. See [LICENSE](LICENSE).
