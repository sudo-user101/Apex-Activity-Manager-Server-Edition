# Changelog

## Unreleased (2026-10-27)

- README: the install steps now start by downloading the release file (and
  checking it); following them from the repository's Download ZIP failed
  with "Cannot open: No such file". No change to the program.

Newest first.

## 2026-10-30 (1.2.0)

- **Panel: full root from the app** (`/api/panel`), off until switched on
  at the server with `sudo apex-server allow panel` (a paired device alone
  can't get a root shell; `deny panel` switches it off; on systemd it adds
  a drop-in that lifts the read-only system for this). Files (list, read,
  write and upload in parts, rename, delete, permissions, owner), a root
  terminal on a real pseudo-terminal (no extra library), packages with
  apt, dnf/yum, apk or zypper (updates, security updates, install, remove,
  restart needed) as background jobs, the firewall with ufw or firewalld
  (SSH and Apex's own port are always kept open and can't be blocked or
  deleted), fail2ban (jails, banned addresses, unban), SSH settings
  (checked with `sshd -t`, put back if refused; passwords can't be turned
  off while nobody has a key), users and their SSH keys (only real keys
  accepted). Every change is logged. Viewing updates, firewall, fail2ban,
  SSH and users works without panel mode.
- Tested on Ubuntu 24.04 (`panel_live_test.go`): all of the above for real,
  including the guards.
- Sites: Nginx Proxy Manager sites show where they forward (its address
  is in `$forward_scheme`, `$server` and `$port`, and proxy_pass comes
  from a shared include). Seen on the owner's server as "–".

## 2026-10-29 (1.1.0)

- **Fixed a leak in 1.0 on servers with Docker:** every reading opened new
  connections to the Docker socket and never closed them (a container's
  stats each time). Measured: 1,030 open sockets and 45 MB after 120
  rounds; now one shared pool: 9 open files and 14.5 MB, flat. Also
  measured: under 1% of one core idle, while read every 3 seconds and with
  the Docker and Sites pages open; a reading answers in 9 ms.
- **Docker Management** (`/api/docker`): containers by stack and the
  manager running each (Dockge, Portainer, Compose), logs, stack up /
  update / down / start / stop / restart, compose files (checked with
  `docker compose config`, the old one kept), images, volumes, networks,
  pruning. Tested on a real Docker daemon (`docker_live_test.go`).
- **Certificates macOS accepts:** 800 days (macOS refuses a server's own
  certificate made for longer, which broke pairing from public and cloud
  addresses), renewed with the same key 60 days before the end and
  swapped in without a restart; 20-year certificates from 1.0 are
  replaced once, keeping their key. Pairing answers with the key's
  fingerprint, so the app accepts renewals.
- Shut down from the app (`power off` action; it answers first, then
  powers off), unpause a container, and each network card's address
  (`mac`) in the readings, for Wake-on-LAN from the app.
- **Sites: reverse proxies.** Finds nginx, Caddy, Traefik and Nginx Proxy
  Manager (on the server or in Docker) and lists every site: its domains,
  where it forwards, HTTPS and the certificate's expiry and issuer, and the
  last 10 minutes of its traffic (requests, a minute, data, 2xx–5xx, top
  paths and clients) from its access log. New API `/api/proxies` and
  `/api/proxy`, and `apex-server sites` (JSON, for checking by hand).
- Add, edit, switch off / on and remove sites on nginx, Caddy and Traefik.
  Apex's sites go in their own files (`apex-<domain>`), never the owner's;
  existing nginx sites can be switched off and on. Every change is checked
  by the proxy itself (`nginx -t`, `caddy validate`, Traefik's API), then
  reloaded and confirmed (nginx: old workers stopped; Traefik: the router
  and its address live); if anything fails, every file is put back.
  Domains and addresses are checked and rewritten before they reach a
  file. HTTPS on nginx uses certbot; Caddy gets certificates itself.
  Nginx Proxy Manager is shown, not changed (its sites live in its own
  database). Every change is logged, with where it came from.
- The systemd service may now write the proxies' folders
  (`ReadWritePaths`: /etc/nginx, /etc/caddy, /etc/traefik, /etc/letsencrypt,
  /var/lib/letsencrypt); the rest of /etc stays read-only. A folder
  elsewhere gets a message saying how to allow it.
- Tested: Ubuntu 24.04 with nginx 1.24, Caddy 2.6.2 and Traefik 3.1.6
  (add, serve through it, traffic, duplicate refused, off, on, edit, a
  change nginx refused undone, remove); installed with systemd and changed
  through the HTTPS API after pairing; unpaired requests refused. Not yet
  tested live: Nginx Proxy Manager (its file and log formats are in the
  tests), certbot (needs a real domain), Traefik in Docker.

## 2026-10-29

- 1.0.1, released: install from a clone of the repository or its Download
  ZIP (`sudo sh install.sh` in the folder): builds with Go 1.22+ if present,
  else downloads this version's release over HTTPS and checks its SHA-256.
  Tested from GitHub with git clone on Ubuntu 24.04 and Download ZIP on
  Alpine 3.20, and building in the Go image. README: install from a clone,
  start / stop / check, update. Release SHA-256 9f17e1bf….

## 2026-10-26

- Moved out of the Mac app's repository into its own: the Server Edition is
  now built, versioned and released on its own. The download now includes
  LICENSE, and no longer carries macOS file attributes (Linux `tar`
  printed warnings about them when unpacking).
- 1.0.0: the Linux service (Go, x86_64 and aarch64), `install.sh` for
  systemd, OpenRC and SysV init, pairing codes and pinned TLS on port 7443,
  the browser page, and the API the Apex Mac app pairs with. Tested on
  Ubuntu 18.04 and 24.04, Debian 12, Fedora 41, Rocky Linux 9, CentOS 7,
  openSUSE Leap 15.6, Amazon Linux 2023 and Alpine 3.20; end to end with the
  app on a systemd Ubuntu. Not yet tested: a real cloud server, Arch, OpenRC
  as the running init system. Pairs with Apex Activity Manager 1.3.0 for Mac.
