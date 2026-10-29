#!/bin/sh
# Apex Activity Manager Server Edition: install, update or remove.
#
#   sudo sh install.sh                 install (or update) on port 7443
#   sudo sh install.sh --port 9000     another port
#   sudo sh install.sh --uninstall     remove it (and its settings)
#
# For Linux with systemd, OpenRC or SysV init, on Intel / AMD (x86_64) and
# ARM (aarch64). Tested on Ubuntu, Debian, Fedora, Rocky, CentOS, openSUSE,
# Amazon Linux and Alpine. Plain sh: no bash needed.
set -eu

PORT=""
UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:-}"; shift 2 ;;
    --port=*) PORT="${1#--port=}"; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
fail() { printf 'Apex: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run it as root: sudo sh install.sh"
[ "$(uname -s)" = Linux ] || fail "the Server Edition is for Linux."

BIN=/usr/local/bin/apex-server
HERE=$(cd "$(dirname "$0")" && pwd)

init_system() {
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then echo systemd
  elif command -v openrc-run >/dev/null 2>&1 || [ -d /run/openrc ]; then echo openrc
  else echo sysv; fi
}
INIT=$(init_system)

stop_service() {
  case "$INIT" in
    systemd) systemctl stop apex-server 2>/dev/null || true ;;
    openrc) rc-service apex-server stop 2>/dev/null || true ;;
    sysv) [ -x /etc/init.d/apex-server ] && /etc/init.d/apex-server stop 2>/dev/null || true ;;
  esac
}

if [ "$UNINSTALL" = 1 ]; then
  stop_service
  case "$INIT" in
    systemd) systemctl disable apex-server 2>/dev/null || true; rm -f /etc/systemd/system/apex-server.service; systemctl daemon-reload ;;
    openrc) rc-update del apex-server default 2>/dev/null || true; rm -f /etc/init.d/apex-server ;;
    sysv) command -v update-rc.d >/dev/null 2>&1 && update-rc.d -f apex-server remove >/dev/null 2>&1 || true
          command -v chkconfig >/dev/null 2>&1 && chkconfig --del apex-server >/dev/null 2>&1 || true
          rm -f /etc/init.d/apex-server ;;
  esac
  rm -f "$BIN"
  rm -rf /etc/apex-server
  say "Apex Server Edition is removed."
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "this processor ($(uname -m)) isn't supported yet: x86_64 and aarch64 are." ;;
esac
SRC="$HERE/apex-server-linux-$ARCH"

# Run from a clone of the repository (no built program next to install.sh):
# build it with Go if it's installed, else download this version's release
# file over HTTPS, check its SHA-256 and take the program from it.
if [ ! -f "$SRC" ]; then
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  VERSION=$(sed -n 's/^var version = "\(.*\)"/\1/p' "$HERE/main.go" 2>/dev/null || true)
  GO=$(command -v go 2>/dev/null || true)
  [ -z "$GO" ] && [ -x /usr/local/go/bin/go ] && GO=/usr/local/go/bin/go
  if [ -n "$GO" ] && [ -f "$HERE/go.mod" ]; then
    say "Building Apex Server Edition $VERSION from this folder with $("$GO" version | cut -d' ' -f3)…"
    (cd "$HERE" && CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH "$GO" build -trimpath -ldflags "-s -w" -o "$WORK/apex-server-linux-$ARCH" .) \
      || fail "the build failed (it needs Go 1.22 or later). Or remove Go from the PATH to download the ready-made program instead."
  elif [ -n "$VERSION" ]; then
    FILE="apex-server-$VERSION-linux.tar.gz"
    URL="https://github.com/sudo-user101/Apex-Activity-Manager-Server-Edition/releases/download/v$VERSION"
    say "Downloading Apex Server Edition $VERSION (the ready-made program for this version)…"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$FILE" "$URL/$FILE" && curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$FILE.sha256" "$URL/$FILE.sha256" \
        || fail "couldn't download $URL/$FILE. Check the internet connection, or install Go 1.22+ to build it here."
    elif command -v wget >/dev/null 2>&1; then
      wget -q -O "$WORK/$FILE" "$URL/$FILE" && wget -q -O "$WORK/$FILE.sha256" "$URL/$FILE.sha256" \
        || fail "couldn't download $URL/$FILE. Check the internet connection, or install Go 1.22+ to build it here."
    else
      fail "neither curl nor wget is installed: install one (or Go 1.22+), or use the release file from the Releases page."
    fi
    WANT=$(cut -d' ' -f1 < "$WORK/$FILE.sha256")
    if command -v sha256sum >/dev/null 2>&1; then GOT=$(sha256sum "$WORK/$FILE" | cut -d' ' -f1)
    else GOT=$(openssl dgst -sha256 "$WORK/$FILE" | sed 's/.*= //'); fi
    [ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || fail "the download's checksum doesn't match ($GOT). Nothing was installed."
    tar xzf "$WORK/$FILE" -C "$WORK" "apex-server-$VERSION/apex-server-linux-$ARCH" \
      && mv "$WORK/apex-server-$VERSION/apex-server-linux-$ARCH" "$WORK/apex-server-linux-$ARCH" \
      || fail "the downloaded file didn't have the program for $ARCH."
    say "Checksum OK."
  else
    fail "apex-server-linux-$ARCH should be next to install.sh (use the release file, or run this from a clone of the repository)."
  fi
  SRC="$WORK/apex-server-linux-$ARCH"
fi

stop_service
install -m 0755 "$SRC" "$BIN.new" 2>/dev/null || { cp "$SRC" "$BIN.new"; chmod 0755 "$BIN.new"; }
mv -f "$BIN.new" "$BIN"

if [ -n "$PORT" ]; then
  "$BIN" setup --port "$PORT" > /tmp/apex-server-welcome.$$
else
  "$BIN" setup > /tmp/apex-server-welcome.$$
fi

case "$INIT" in
  systemd)
    cat > /etc/systemd/system/apex-server.service <<'UNIT'
[Unit]
Description=Apex Activity Manager Server Edition
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/apex-server run
Restart=always
RestartSec=3
# It runs as root to see every process and manage services, but can't gain
# more than that or change the system's files beyond its own settings.
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/etc/apex-server

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now apex-server >/dev/null 2>&1
    systemctl restart apex-server ;;
  openrc)
    cat > /etc/init.d/apex-server <<'RC'
#!/sbin/openrc-run
description="Apex Activity Manager Server Edition"
command=/usr/local/bin/apex-server
command_args=run
supervisor=supervise-daemon
respawn_delay=3
output_log=/var/log/apex-server.log
error_log=/var/log/apex-server.log
depend() { need net; }
RC
    chmod 0755 /etc/init.d/apex-server
    rc-update add apex-server default >/dev/null 2>&1 || true
    rc-service apex-server restart >/dev/null 2>&1 || rc-service apex-server start ;;
  sysv)
    mkdir -p /etc/init.d
    cat > /etc/init.d/apex-server <<'SYSV'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          apex-server
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Apex Activity Manager Server Edition
### END INIT INFO
PIDFILE=/run/apex-server.pid
# The keeper loop's id, only if that process really is it (a stale file can
# name a process id that's been reused by something else).
keeper() {
  [ -f $PIDFILE ] || return 1
  p=$(cat $PIDFILE)
  grep -q "apex-server-keeper" "/proc/$p/cmdline" 2>/dev/null && echo "$p"
}
case "$1" in
  start)
    [ -n "$(keeper)" ] && exit 0
    # Its own session, so it outlives the shell that started it; restarted if it stops.
    if command -v setsid >/dev/null 2>&1; then
      setsid sh -c 'while :; do /usr/local/bin/apex-server run >> /var/log/apex-server.log 2>&1; sleep 3; done' apex-server-keeper </dev/null >/dev/null 2>&1 &
    else
      nohup sh -c 'while :; do /usr/local/bin/apex-server run >> /var/log/apex-server.log 2>&1; sleep 3; done' apex-server-keeper </dev/null >/dev/null 2>&1 &
    fi
    echo $! > $PIDFILE ;;
  stop)
    p=$(keeper) && kill "$p" 2>/dev/null
    rm -f $PIDFILE
    for p in $(ls /proc 2>/dev/null | grep '^[0-9]*$'); do
      # The program itself (not this script, which shares its name).
      [ "$(readlink /proc/$p/exe 2>/dev/null)" = /usr/local/bin/apex-server ] && kill "$p" 2>/dev/null
    done
    true ;;
  restart) "$0" stop; sleep 1; "$0" start ;;
  status) [ -n "$(keeper)" ] && echo running || { echo stopped; exit 3; } ;;
  *) echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
SYSV
    chmod 0755 /etc/init.d/apex-server
    if command -v update-rc.d >/dev/null 2>&1; then update-rc.d apex-server defaults >/dev/null 2>&1 || true
    elif command -v chkconfig >/dev/null 2>&1; then chkconfig --add apex-server >/dev/null 2>&1 || true; fi
    /etc/init.d/apex-server restart ;;
esac

# Is it answering?
P=$(sed -n 's/.*"port": *\([0-9]*\).*/\1/p' /etc/apex-server/config.json 2>/dev/null)
P=${P:-7443}
ok=0
for i in 1 2 3 4 5 6 7 8 9 10; do
  if command -v curl >/dev/null 2>&1; then curl -ksf "https://127.0.0.1:$P/api/hello" >/dev/null 2>&1 && { ok=1; break; }
  elif command -v wget >/dev/null 2>&1; then wget -q --no-check-certificate -O /dev/null "https://127.0.0.1:$P/api/hello" 2>/dev/null && { ok=1; break; }
  else ok=2; break; fi
  sleep 1
done

cat /tmp/apex-server-welcome.$$
rm -f /tmp/apex-server-welcome.$$
if [ "$ok" = 1 ]; then say "  Running ($INIT) and answering on port $P."
elif [ "$ok" = 0 ]; then say "  Installed ($INIT), but it isn't answering on port $P yet. See: $( [ "$INIT" = systemd ] && echo 'journalctl -u apex-server' || echo 'tail /var/log/apex-server.log')"
else say "  Installed ($INIT) on port $P."; fi

# The firewall: say what to open (Apex never changes it by itself).
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  say "  The firewall (ufw) is on. To reach Apex from your Mac: sudo ufw allow $P/tcp"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  say "  The firewall (firewalld) is on. To reach Apex from your Mac: sudo firewall-cmd --permanent --add-port=$P/tcp && sudo firewall-cmd --reload"
fi
say "  Cloud servers: also allow TCP $P in the provider's firewall / security group, ideally only from your own address."
say ""
