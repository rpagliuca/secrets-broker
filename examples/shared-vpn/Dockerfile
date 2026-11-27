# OpenVPN client for the broker: each bridge listens on a Unix socket in the
# command's directory, never on a port of the machine.
FROM alpine:3.20
RUN apk add --no-cache openvpn socat iproute2
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
