# Changelog

## 1.0.1 (2026-10-29)

- Install from a clone of the repository (or its Download ZIP): run
  `sudo sh install.sh` in the folder. With Go 1.22+ it builds the program
  there; otherwise it downloads this version's release file over HTTPS,
  checks its SHA-256, and installs nothing if it doesn't match. Tested from
  a clone on Ubuntu 24.04 (curl), the Go image (build) and Alpine 3.20
  (BusyBox wget).
- README: install from a clone or the ZIP, starting, stopping and checking
  the service, updating.
- README (2026-10-27): the release-file steps start by downloading and
  checking it. No change to the program itself.

## 1.0.0 (2026-10-26)

- The first release: a task manager for a Linux server. Every process,
  service, disk, network interface, container, GPU and signed-in user, live,
  in Apex Activity Manager 1.3.0 or later on a Mac, or in a browser.
- End processes and start, stop or restart services and containers, after
  you confirm. Every action is logged.
- One static program for x86_64 and aarch64; `install.sh` sets it up as a
  service with systemd, OpenRC or SysV init.
- Encrypted (TLS 1.2+) on its own port, 7443 by default. Devices pair with a
  one-time code; the app remembers the server's certificate and refuses any
  other.
- Tested on Ubuntu 18.04 and 24.04, Debian 12, Fedora 41, Rocky Linux 9,
  CentOS 7, openSUSE Leap 15.6, Amazon Linux 2023 and Alpine 3.20, and end to
  end with the Mac app on Ubuntu with systemd. Not tested yet: a cloud
  server, Arch Linux, and OpenRC as the running init system.
