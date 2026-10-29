# Apex Activity Manager Server Edition

A task manager for a Linux server: every process, service, disk, network
interface, container and signed-in user, live, in the Apex app on your Mac or
in a browser. It runs as a service on its own port (7443), encrypted, and only
devices you pair with a one-time code can see or change anything.

Works with **Apex Activity Manager 1.3.0 or later** for Mac
([download](https://github.com/sudo-user101/Apex-Activity-Manager-MacOSX/releases/latest)),
and with any modern browser.

One static program, no dependencies, for x86_64 and aarch64 Linux with
systemd, OpenRC or SysV init. Tested on Ubuntu 18.04 and 24.04 (with
systemd), Debian 12, Fedora 41, Rocky Linux 9, CentOS 7, openSUSE Leap 15.6,
Amazon Linux 2023 and Alpine 3.20.

## Install

On the Linux server, download the release file, check it, unpack it and run
the installer:

    curl -fLO https://github.com/sudo-user101/Apex-Activity-Manager-Server-Edition/releases/latest/download/apex-server-1.0.1-linux.tar.gz
    curl -fLO https://github.com/sudo-user101/Apex-Activity-Manager-Server-Edition/releases/latest/download/apex-server-1.0.1-linux.tar.gz.sha256
    sha256sum -c apex-server-1.0.1-linux.tar.gz.sha256
    tar xzf apex-server-1.0.1-linux.tar.gz
    cd apex-server-1.0.1
    sudo sh install.sh                # or: sudo sh install.sh --port 9000

No `curl`? Use `wget` with the same addresses, or download both files from
the [Releases](https://github.com/sudo-user101/Apex-Activity-Manager-Server-Edition/releases)
page and run the commands from the folder they're in (usually `~/Downloads`).

### Or from a clone of this repository

Clone it (or use **Code › Download ZIP** and unzip it), go into the folder
and run the same installer:

    git clone https://github.com/sudo-user101/Apex-Activity-Manager-Server-Edition.git
    cd Apex-Activity-Manager-Server-Edition
    sudo sh install.sh                # or: sudo sh install.sh --port 9000

With the ZIP instead of `git`:

    curl -fLO https://github.com/sudo-user101/Apex-Activity-Manager-Server-Edition/archive/refs/heads/main.zip
    unzip main.zip                    # makes Apex-Activity-Manager-Server-Edition-main
    cd Apex-Activity-Manager-Server-Edition-main
    sudo sh install.sh

A clone holds the source code, not the built program, so the installer
gets the program for you:

- **Go 1.22 or later installed?** It builds the program from the folder
  (about a minute).
- **No Go?** It downloads this version's release file from GitHub over
  HTTPS (with `curl` or `wget`), checks its SHA-256 checksum, and installs
  nothing if it doesn't match.
- **Neither Go nor `curl` / `wget`?** It stops and says what to install.
  `git`, `curl` and `unzip` come from the system's packages, for example
  `sudo apt install git curl unzip` (Ubuntu, Debian), `sudo dnf install git
  curl unzip` (Fedora, Rocky), `sudo apk add git curl unzip` (Alpine).

Tested from a clone on Ubuntu 24.04 (download with `curl`), the official Go
image (built from the folder) and Alpine 3.20 (download with BusyBox `wget`).

### Start, stop and open it

The installer starts it straight away and sets it to start with the server;
there's nothing else to launch. It prints the address and a pairing code
(below). To see that it's running, or to start and stop it yourself:

    sudo apex-server status                         address, port, fingerprint
    sudo systemctl status apex-server               systemd (most servers)
    sudo systemctl restart apex-server
    sudo rc-service apex-server restart             OpenRC (Alpine)
    sudo /etc/init.d/apex-server restart            SysV init (older systems)

To update later: `git pull` in the folder (or download the newer release
file) and run `sudo sh install.sh` again; paired devices and settings stay.

It prints the server's address, a pairing code and its certificate's
fingerprint. In Apex on your Mac: This Mac menu › Add Server…, choose
**Apex Server Edition**, enter the address and the code, and check the
fingerprint matches. Or open `https://<address>:7443` in a browser.

Open the port in the server's firewall (the installer says how), and for a
cloud server in its security group, ideally only from your own address.

## Manage it

    sudo apex-server pair             a new pairing code (valid 24 hours)
    sudo apex-server devices          paired devices
    sudo apex-server devices remove ID
    sudo apex-server status           addresses, port, fingerprint
    sudo sh install.sh --uninstall    remove it and its settings

## What it can change

Only what you ask it to, after you confirm: end a process, start / stop /
restart a service or a container. Every action is logged with where it came
from (`journalctl -u apex-server`, or /var/log/apex-server.log).

## Security

- TLS 1.2+ with the server's own certificate (made on first start, kept in
  /etc/apex-server, root only). Apex remembers its fingerprint and refuses
  any other certificate.
- Pairing codes expire after 24 hours; 10 wrong codes from one address lock
  it out for 15 minutes. Each device gets its own token; only its SHA-256 is
  stored on the server, and any device can be removed.
- The systemd service runs with NoNewPrivileges and a read-only system.

## Every computer

Apex's direction is simple: **if it's a computer, it can run Apex.** One app,
the same pages and the same plain words on every operating system and every
kind of hardware:

- **macOS:** Apple silicon and Intel.
- **Windows:** x64 and ARM64 PCs.
- **Linux:** desktops and servers, x86_64 and ARM (64- and 32-bit), the main
  distributions and the small ones.
- More to come, as they're tested: older versions of each system, and other
  operating systems.

Some features depend on what each system allows (fan control or battery
charge limits, for example), so an edition may have fewer of them. When it
does, the app says so plainly instead of hiding the page. Install should
never be the thing that stops you.

## Building

    ./build.sh        # vet, test, then dist/apex-server-<version>-linux.tar.gz

Needs Go 1.22 or later; nothing else (standard library only, static
programs). The readings it sends are the shape the Apex Mac app reads, so a
change to a field's name or type has to ship with the app.

## License

Source-available under the PolyForm Strict License 1.0.0 (see LICENSE).
Copyright © 2026 CyberNet Labs.
