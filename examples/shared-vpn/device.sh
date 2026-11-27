#!/bin/sh
# One device of a remote network per broker command, one VPN behind them.
#
#   device.sh up   <command dir> <file.sock>
#   device.sh down <command dir> <file.sock>
#
# Each device is its own command in the broker, with its own name and grant.
# When the VPN account allows one connection at a time, they all share one
# container: the first "up" starts it, with the secrets the broker wrote in
# that command's directory, and the last "down" stops it. The command's
# directory gets only a link to its device's socket, and the broker forwards
# only a client granted that device to that socket.
set -eu
act=$1
dir=$2
sock=$3
base=$(dirname "$dir")
shared=$base/shared-vpn
users=$base/shared-vpn.users
here=$(dirname "$0")
compose() { VPN_DIR=$shared /usr/bin/docker compose -f "$here/compose.yml" "$@"; }

case $act in
up)
	mkdir -p -m 700 "$users"
	if ! /usr/bin/docker ps -q --filter name=^secrets-broker-shared-vpn$ | grep -q .; then
		rm -rf "$shared"
		mkdir -m 700 "$shared"
		cp "$dir/client.ovpn" "$dir/auth.txt" "$shared/"
		chmod 600 "$shared/client.ovpn" "$shared/auth.txt"
		compose up -d --build
	fi
	: >"$users/$(basename "$dir")"
	ln -sfn "$shared/$sock" "$dir/$sock"
	# The socket appears only with the VPN up: start returns when it is ready.
	i=0
	until [ -S "$shared/$sock" ]; do
		i=$((i + 1))
		if [ "$i" -gt 90 ]; then
			echo "the VPN was not up in 90 s; last lines of the container:"
			/usr/bin/docker logs --tail 20 secrets-broker-shared-vpn 2>&1 || true
			exit 1
		fi
		sleep 1
	done
	echo "device up: $sock (shared VPN, up)"
	;;
down)
	rm -f "$dir/$sock" "$users/$(basename "$dir")"
	if [ -z "$(ls -A "$users" 2>/dev/null)" ]; then
		compose down
		rm -rf "$shared" "$users"
		echo "last device down: VPN stopped"
	else
		echo "device down: $sock; the VPN stays for the others"
	fi
	;;
*)
	echo "usage: $0 up|down <dir> <file.sock>" >&2
	exit 2
	;;
esac
