#!/bin/sh
# Brings the VPN up and makes one bridge per device, each on a Unix socket in
# /vpn (the shared directory, readable only by the broker's user):
#   client.ovpn  VPN configuration      (written by the broker)
#   auth.txt     line 1 user, line 2 password (written by the broker)
#   *.sock       bridges made here
# BRIDGES: "file.sock:host:port" separated by spaces. The VPN stays inside the
# container: the machine gets no route, and a pushed default route is ignored.
set -eu
for f in /vpn/client.ovpn /vpn/auth.txt; do
	[ -s "$f" ] || { echo "missing $f"; exit 1; }
done
: "${BRIDGES:?set BRIDGES}"
sed '/^auth-user-pass/d' /vpn/client.ovpn >/tmp/client.ovpn
printf '\nauth-user-pass /vpn/auth.txt\npull-filter ignore "redirect-gateway"\n' >>/tmp/client.ovpn
openvpn --config /tmp/client.ovpn --verb 3 &
VPN=$!
i=0
until ip -4 addr show tun0 2>/dev/null | grep -q inet; do
	kill -0 "$VPN" 2>/dev/null || { echo "OpenVPN exited (AUTH_FAILED? see above)"; exit 1; }
	i=$((i + 1))
	[ "$i" -lt 60 ] || { echo "tun0 not up in 60 s"; exit 1; }
	sleep 1
done
echo "VPN up"
for b in $BRIDGES; do
	file=${b%%:*}
	to=${b#*:}
	echo "bridge $file -> $to"
	# -d -d: each connection and the result of the connect go to the log.
	# mode=666: the directory (0700, the broker's) protects, not the socket.
	socat -d -d "UNIX-LISTEN:/vpn/$file,fork,unlink-early,mode=666" "TCP:$to,connect-timeout=5" &
done
# If the VPN goes down, the container goes down with it.
wait "$VPN"
echo "OpenVPN ended"
exit 1
