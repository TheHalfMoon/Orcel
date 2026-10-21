# Orcel on Linux (XP-17)

Orcel runs per user on Linux. `orceld` remains the only authority. The
packages add no system service, setuid binary, network listener or
maintainer script, and store no state outside the user's private XDG state
root.

## Layout

The layout is defined in `crates/orcel-lifecycle/src/linux.rs` and tested on
every OS.

| Purpose | Path |
| --- | --- |
| State: audit, approvals, trust, leases | `$XDG_STATE_HOME/orcel`, else `~/.local/state/orcel`. This is the XP-01 root, mode 0700. The defaults are never under `/tmp`. XP-01 accepts an ancestor that others can write only when it is root-owned and sticky, like `/tmp` itself, so an explicit `XDG_STATE_HOME=/tmp/x` is accepted: the 0700 root still keeps other users out, but another user can pre-create the path and leave Orcel without state. Keep `XDG_STATE_HOME` out of shared directories (#369 item 5). |
| `orceld` from the deb or rpm | `/usr/lib/orcel/orceld` (root-owned, 0755) |
| `orceld` from the tarball | `~/.local/share/orcel/bin/orceld` |
| Contained-tier helper and its pin (XP-13b) | `orcel-contain` and `orcel-contain.sha256` beside `orceld`, in either layout. `orceld` pins the helper by that file and looks nowhere else. |
| XP-10 approval dialog helper | `orcel-approval-helper-linux` beside `orceld`, in either layout. `orceld` looks there first, then `/usr/libexec/orcel/`, never on `PATH`. |
| XP-10 polkit action (STRONG) | `/usr/share/polkit-1/actions/ai.orcel.approve.policy` from the deb or rpm. The tarball ships it in `doc/`: polkit reads actions only from that root-owned directory, so STRONG approvals of a tarball install fail closed until an administrator copies it there. |
| User units from the deb or rpm | `/usr/lib/systemd/user/orceld.socket`, `orceld@.service` |
| User units from the tarball | `~/.config/systemd/user/` |
| Workspaces for `orceld` | `$XDG_CONFIG_HOME/orcel/orceld.env`, else `~/.config/orcel/orceld.env` |
| Socket | `$XDG_RUNTIME_DIR/orcel/orceld.sock` (0600, in a 0700 directory) |

## Install

Each package installs files only. No user gets a running service until that
user enables it.

### deb (Ubuntu 24.04 and later) or rpm (Fedora 41 and later)

```sh
sudo apt install ./orcel_<version>-1_amd64.deb      # or: sudo dnf install ./orcel-<version>-1.x86_64.rpm
```

### Tarball (no root)

```sh
mkdir -p ~/.local/share/orcel ~/.config/systemd/user
tar -xzf orcel-<version>-linux-x86_64.tar.gz --strip-components=1 -C ~/.local/share/orcel
install -m 0644 ~/.local/share/orcel/systemd/orceld.socket ~/.local/share/orcel/systemd/orceld@.service ~/.config/systemd/user/
```

### Configure and start

Run these steps as the user, never with `sudo`:

```sh
mkdir -p ~/.config/orcel && chmod 0700 ~/.config/orcel
printf '%s\n' "ORCEL_WORKSPACES_JSON='[{\"id\":\"main\",\"root\":\"$HOME/code\"}]'" > ~/.config/orcel/orceld.env
chmod 0600 ~/.config/orcel/orceld.env
systemctl --user daemon-reload
systemctl --user enable --now orceld.socket
```

Verify each download against `SHA256SUMS-linux.txt` (`sha256sum -c`) and
with `gh attestation verify <file> --repo TheHalfMoon/Orcel`.

### Uninstall

Uninstalling is also the rollback. Run
`systemctl --user disable --now orceld.socket`, then
`sudo apt remove orcel` or `sudo dnf remove orcel`. For a tarball install,
delete `~/.local/share/orcel` and the two units instead. Your state in
`~/.local/state/orcel` is kept.

## Why a socket unit

`orceld` reads JSON lines on stdin and writes them on stdout. It opens no
listener of its own. With `Accept=yes`, `orceld.socket` starts one
`orceld@.service` per connection and passes that connection as its stdin
and stdout. This matches how `orcel mcp stdio` and the CLI already use
`orceld`: one fresh process per client.

A plain long-running `orceld.service` would read end-of-file at once and
exit. The socket is `AF_UNIX` in the user's 0700 runtime directory with
mode 0600, so only that user's processes can connect. Those processes could
already run `orceld` themselves, so the socket grants no new authority.

The read-only app API (CR-01) binds `$XDG_RUNTIME_DIR/orcel/app-api.sock`
in the same directory. Every per-connection instance tries to take it, but
an advisory lock on `app-api.lock` beside it admits one holder at a time;
the others retry every 5 seconds and never touch the holder's socket
(#375 item 3). The lock file stays after the holder exits, by design.

## Service hardening

Every directive below works in a per-user service manager without user
namespaces. Unit tests in `linux.rs` keep them in the unit.

| Directive | Why |
| --- | --- |
| `NoNewPrivileges=yes` | Neither `orceld` nor anything it starts (git, registered executables) can gain privileges through setuid, setgid or file capabilities. |
| `RestrictSUIDSGID=yes` | `orceld` and its children cannot create setuid or setgid files. |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | `AF_UNIX` is needed for journald, D-Bus (polkit approvals, XP-10) and ssh-agent. `AF_INET` and `AF_INET6` are needed for outbound git fetch and push and for the network provider. Netlink, packet, Bluetooth and every other family are refused. `orceld` never calls `bind` or `listen`. |
| `RestrictNamespaces=yes` | Namespace creation, a common step in sandbox escapes, is refused for `orceld` and its children. |
| `RestrictRealtime=yes` | Realtime scheduling is refused, so a runaway child cannot starve the desktop. |
| `LockPersonality=yes` | The execution domain is locked, which blocks `personality(2)` tricks such as `READ_IMPLIES_EXEC`. |
| `SystemCallArchitectures=native` | Only native-ABI system calls are allowed. Compat-ABI calls, which can bypass the filters above, are refused. |
| `UMask=0077` | Every file `orceld` creates is owner-only, on top of the 0600 and 0700 modes the state store already sets. |
| `KillMode=control-group` | When a connection ends, every process the instance started ends too. This is the Linux counterpart of the Windows kill-on-close Job Object. |
| `Delegate=yes` | XP-13b: the instance's cgroup is delegated to `orceld`. The Safe tier puts each registered executable in its own child cgroup and ends the whole tree with `cgroup.kill`, including descendants that left the process group. Delegation lets `orceld` create child cgroups and move its own children into them. It grants no other rights: no controllers are enabled, so no resource limits are lifted. The cleanup is best effort against a cooperative child: the delegated subtree belongs to the user, so a child running as the user could move itself to another cgroup in it before `cgroup.kill`. `KillMode=control-group` still ends it when the instance stops. |
| `EnvironmentFile=-%E/orcel/orceld.env` | Workspaces come from the user's own config. When the file is missing, `orceld` refuses to start (fail closed). |

### Directives left out

- `ProtectSystem=strict`, `ProtectHome=`, `PrivateTmp=`, `PrivateDevices=`
  and `ProtectKernel*=` all need a mount namespace. In a user service
  manager that means an implicit `PrivateUsers=yes`. Only the user's own
  uid is mapped, so root-owned `/` and `/home` appear to be owned by
  `nobody`. XP-01's `ensure_private_dir` then refuses the state root as
  foreign-owned, and `orceld` cannot open its audit log. Ubuntu 24.04 also
  restricts unprivileged user namespaces through AppArmor. The CI job
  `Linux packages` probes these directives with a drop-in and records the
  outcome.
- `MemoryDenyWriteExecute=yes` and `SystemCallFilter=` are inherited by every
  child `orceld` starts. Registered executables and JIT runtimes such as
  Node.js would break.
- `CapabilityBoundingSet=` and the `IPAddress*` and `SocketBind*` options need
  privileges that a user manager does not have. A user service holds no
  capabilities anyway.

`systemd-analyze security --user orceld@probe.service` runs in the CI job
`Linux packages` on the installed unit and requires each directive above
that it scores (`NoNewPrivileges=`, `RestrictSUIDSGID=`,
`RestrictAddressFamilies=`, `RestrictNamespaces=`, `RestrictRealtime=`,
`LockPersonality=`, `SystemCallArchitectures=`) to be reported as applied
(#369 item 4).

## Approvals (XP-10)

The deb and rpm install the GTK 4 approval dialog helper,
`/usr/lib/orcel/orcel-approval-helper-linux`, and the polkit action
`/usr/share/polkit-1/actions/ai.orcel.approve.policy` (`allow_active=auth_self`,
nothing for inactive or remote sessions). They *recommend* GTK 4
(`libgtk-4-1` / `gtk4`) and polkit (`polkitd` / `polkit`) instead of
requiring them. A headless server runs `orceld` without them, and its
approvals are unavailable there anyway: no graphical session can show the
dialog, and a missing library or `pkcheck` fails closed as unavailable,
never as approved. The helper makes itself non-dumpable before it reads a
request (#373 item 1).

The tarball carries the helper in `bin/` and the action in `doc/`. polkit
reads actions only from its root-owned directory, so a tarball install's
STRONG approvals fail closed until an administrator runs
`sudo install -m 0644 ~/.local/share/orcel/doc/ai.orcel.approve.policy /usr/share/polkit-1/actions/`.

Linux approvals are implemented but not release-qualified: the GNOME and KDE
live check in SECURITY_INTEGRATION.md (including the socket-activated
user-service case) has NOT RUN on a real desktop.
