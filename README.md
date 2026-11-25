# secrets-broker

A small HTTPS proxy that lets an untrusted client, such as an AI agent, use an
API credential without ever holding it.

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

Each item has a test in `broker/proxy_test.go`.

| Attack | Result |
| --- | --- |
| Send the request to a host the attacker controls | `403` at `CONNECT`; nothing leaves the broker |
| Open a tunnel to the right host and use another `Host` header | `421`; nothing leaves the broker |
| Open a tunnel to the right host and present another SNI | TLS handshake fails |
| Make the service redirect to another host | the `3xx` is returned as is; the follow-up is refused |
| Write a placeholder in the body or URL hoping it is replaced by the secret | nothing is ever replaced; only the `Authorization` header is set |
| Use a credential of another group | `403` |
| Edit the configuration to point a secret at a new host | `403`: the host list is stored inside the encrypted secret |
| Make the service echo the request headers (`TRACE`, debug endpoints) | `TRACE` is refused; a response containing the credential is cut |
| Ask the service for an encoding the broker cannot read | the broker negotiates the encoding itself; an unreadable response is refused |

## What is not covered

- **Misuse inside the rules.** A client that is allowed to use a credential
  can do anything that credential can do on that host, including reading data
  and sending it elsewhere by other means. Use credentials with the smallest
  scope the service offers, and `methods` for read-only access. Restricting
  paths is not implemented.
- **Credentials that create credentials.** If the service lets a token create
  another token or key, the client can ask for one and read it in the
  response.
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
| `credentials[].name` | Name in the audit log, and the secret name unless `secret` is set |
| `credentials[].hosts` | Exact, lower-case host names; no wildcard, no port |
| `credentials[].groups` | Client groups allowed to use the credential |
| `credentials[].scheme` | `bearer`, or `basic` with `username` |
| `credentials[].methods` | Optional list of allowed HTTP methods |

A host and group pair may be served by one credential only, so there is never
a choice of which secret to send.

Changing the configuration requires a restart, and a restart leaves the broker
sealed. A change of policy therefore only takes effect when the person holding
the vault key unseals again.

`SIGHUP` re-reads the secrets directory (with the key already in memory) and
the tokens file.

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
```

A deployment can keep `agestore` and replace the authenticator (for example
with the session tokens of whatever launches the agents) and the auditor, then
call `broker.Run`.

## Not in this version

- Short-lived credentials issued by the service (cloud STS, app installation
  tokens) instead of a stored secret.
- Path rules per credential.
- Pass-through for hosts without a credential, and an egress allow-list.

## Development

```sh
make check   # gofmt, go vet, tests with the race detector, govulncheck
```

Dependencies are limited to the standard library and `filippo.io/age`.

## License

MIT. See [LICENSE](LICENSE).
