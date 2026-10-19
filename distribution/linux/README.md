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
| State: audit, approvals, trust, leases | `$XDG_STATE_HOME/orcel`, else `~/.local/state/orcel`. This is the XP-01 root, mode 0700, and is never under `/tmp`. |
| `orceld` from the deb or rpm | `/usr/lib/orcel/orceld` (root-owned, 0755) |
| `orceld` from the tarball | `~/.local/share/orcel/bin/orceld` |
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

## Polkit action

`distribution/linux/ai.orcel.approve.policy` belongs to XP-10. It is the
only file that would need root to install, and the packages add it once it
exists.
