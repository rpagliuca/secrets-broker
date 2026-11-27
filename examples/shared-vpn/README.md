# One VPN, one grant per device

The broker runs commands for clients (see "Commands" in the main README).
Here each device of a remote network is a command of its own, so the
approver grants a PLC, a meter or a host one by one, while a single VPN
connection serves them all (useful when the account allows one at a time).
An SSH target can also reach a host through one of these commands (`via`):
the broker brings the VPN up and logs in with its key.

```json
"commands": [
  {"name": "org/vpn/site/plc1-modbus-502", "groups": ["ops"],
   "files": [{"secret": "vpn-ovpn", "name": "client.ovpn"}, {"secret": "vpn-auth", "name": "auth.txt"}],
   "start": ["/bin/sh", "/etc/secrets-broker/shared-vpn/device.sh", "up", "{dir}", "plc1.sock"],
   "stop":  ["/bin/sh", "/etc/secrets-broker/shared-vpn/device.sh", "down", "{dir}", "plc1.sock"],
   "forwards": {"192.168.1.10:502": "plc1.sock"}},
  {"name": "org/vpn/site/host-ssh-22", "groups": ["ops"],
   "files": [{"secret": "vpn-ovpn", "name": "client.ovpn"}, {"secret": "vpn-auth", "name": "auth.txt"}],
   "start": ["/bin/sh", "/etc/secrets-broker/shared-vpn/device.sh", "up", "{dir}", "host.sock"],
   "stop":  ["/bin/sh", "/etc/secrets-broker/shared-vpn/device.sh", "down", "{dir}", "host.sock"],
   "forwards": {"192.168.1.30:22": "host.sock"}}
],
"ssh": {"targets": [
  {"name": "org/ssh/host/shell-ops", "secret": "ssh-key", "address": "192.168.1.30:22", "user": "ops",
   "host_keys": ["ssh-ed25519 AAAA..."], "groups": ["ops"], "via": "org/vpn/site/host-ssh-22"}
]}
```

The two VPN secrets are bound to every command that uses them
(`secrets-broker encrypt -config ...` finds them). A client starts its device
with `POST /commands/<name>/start`, reaches it with
`ssh -L <port>:<host>:<port> -l <name>` through the broker's SSH proxy, and
stops it with `/stop`; the broker also stops it when the grant ends.
