#!/bin/sh
set -eu

fail() {
  echo "CLOUDFLARED_TUNNEL_PEER_IP must be one RFC1918 private literal IPv4 address" >&2
  exit 1
}

peer="${CLOUDFLARED_TUNNEL_PEER_IP:-}"
case "$peer" in
  ""|*/*|*[^0-9.]*|.*|*.) fail ;;
esac

set -f
previous_ifs="$IFS"
IFS=.
set -- $peer
IFS="$previous_ifs"

[ "$#" -eq 4 ] || fail
for octet in "$@"; do
  case "$octet" in
    0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]) ;;
    *) fail ;;
  esac
  [ "$octet" -le 255 ] 2>/dev/null || fail
done

[ "$peer" != "0.0.0.0" ] || fail

case "$1" in
  10) ;;
  172) [ "$2" -ge 16 ] 2>/dev/null && [ "$2" -le 31 ] 2>/dev/null || fail ;;
  192) [ "$2" -eq 168 ] 2>/dev/null || fail ;;
  *) fail ;;
esac
