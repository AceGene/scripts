#!/usr/bin/env bash
## One time host setup for `vpn.py --vpn protonvpn`.
##
## Installs a Proton VPN WireGuard config for wg-quick and, optionally, the
## passwordless sudo entries vpn.py needs to run unattended from cron.
##
## Usage:
##   ./setup-protonvpn-host.sh [--iface NAME] [--user NAME] [--lan CIDR,...] [--dry-run] <config.conf>
##
## The config comes from account.protonvpn.com -> Downloads -> WireGuard
## configuration. Its `DNS =` line is rewritten into resolvectl PostUp/PostDown
## hooks, because wg-quick only implements `DNS =` via the `resolvconf` binary,
## which systemd-resolved systems do not ship.
##
## Also installs the kill switch ruleset vpn.py loads, and the sudoers entries it
## needs to run unattended. Everything vpn.py may run as root is a fixed command
## over root owned files, so a process running as this user cannot change what the
## kill switch does without a password.

set -eu

_print_usage() {
    sed -n '2,15p' "${0}" | sed 's/^## \?//'
}

_err() {
    echo "ERROR: ${*}" >&2
    exit 1
}

_print_prereqs() {
    cat <<'EOF'
Prerequisites for `vpn.py --vpn protonvpn`:
  * wireguard-tools  - wg, wg-quick            (apt install wireguard-tools)
  * nftables         - nft, for the kill switch (apt install nftables)
  * a DNS integration - systemd-resolved (resolvectl) or openresolv (resolvconf)
  * python3          - used here to normalise IPv6 prefixes
  * sudo/visudo      - to install the NOPASSWD entries vpn.py needs from cron
  * a Proton VPN WireGuard config file (see below)
EOF
}

_print_where_to_get_a_config() {
    cat <<'EOF'
Where to get the config file:
  1. Sign in at https://account.protonvpn.com -> Downloads -> WireGuard configuration
  2. Pick a P2P server (double arrow icon) and enable NAT-PMP (port forwarding)
     if this host will forward ports; leave IPv6 on if the LAN uses it
  3. Create, download, and pass the .conf path to this script, e.g.
       sudo SCRIPT_PATH ~/Downloads/wg-US-IL-323.conf
  Use a config per machine: Proton binds one endpoint per key, so two hosts
  sharing a config will fight over the tunnel and both will flap.
EOF
}

_check_prereqs() {
    local missing=''

    command -v wg >/dev/null 2>&1 || missing="${missing} wireguard-tools(wg)"
    command -v wg-quick >/dev/null 2>&1 || missing="${missing} wireguard-tools(wg-quick)"
    command -v nft >/dev/null 2>&1 || missing="${missing} nftables(nft)"
    command -v python3 >/dev/null 2>&1 || missing="${missing} python3"
    command -v visudo >/dev/null 2>&1 || missing="${missing} sudo(visudo)"
    if ! command -v resolvconf >/dev/null 2>&1 && ! command -v resolvectl >/dev/null 2>&1; then
        missing="${missing} openresolv(resolvconf)-or-systemd-resolved(resolvectl)"
    fi
    ## wg-quick needs either the kernel module or the userspace implementation
    if ! modinfo wireguard >/dev/null 2>&1 && ! command -v wireguard-go >/dev/null 2>&1; then
        missing="${missing} wireguard-kernel-module-or-wireguard-go"
    fi

    if [ "${missing}" != '' ]; then
        echo >&2 'ERROR: missing prerequisites:'
        local item=''
        for item in ${missing}; do echo >&2 "    - ${item}"; done
        echo >&2 ''
        _print_prereqs >&2
        echo >&2 ''
        echo >&2 'Install what is listed above, then run this script again.'
        exit 1
    fi
    echo 'INFO: prerequisites satisfied (wg, wg-quick, nft, python3, visudo, DNS integration)'
}

_detect_lan6_networks() {
    ## Every global IPv6 prefix on a real LAN interface; tunnels, docker and
    ## loopback are excluded because traffic to those is matched by other rules.
    ## Overlapping prefixes are collapsed: nft builds an interval set here and
    ## rejects the whole ruleset if one element contains another (a /128 host
    ## address inside its own /64 is the usual way to trip this).
    ip -6 -o addr show scope global 2>/dev/null |
        awk '$2 !~ /^(lo|docker|br-|veth|proton|wg|tun|tap)/ {print $4}' |
        python3 -c '
import ipaddress, sys
nets = {ipaddress.ip_network(line.strip(), strict=False) for line in sys.stdin if line.strip() != ""}
print(",".join(str(n) for n in ipaddress.collapse_addresses(nets)))
'
}

_killswitch_ruleset() {
    local iface="${1}"
    local lan_networks="${2}"
    local wg_port="${3}"
    local lan6_networks="${4}"

    ## `table` then `delete table` in one transaction makes the load idempotent: the
    ## first line creates the table if absent so the delete cannot fail, and the
    ## rebuild is atomic, so there is never a window with no rules.
    ##
    ## Only the output hook is filtered. Forwarded packets (docker containers) are
    ## left alone: a drop policy there breaks container networking, and the
    ## qBittorrent container runs its own kill switch.
    cat <<EOF
## Installed by setup-protonvpn-host.sh; loaded by vpn.py --killswitch
table inet vpn-killswitch
delete table inet vpn-killswitch
table inet vpn-killswitch {
    chain output {
        type filter hook output priority filter; policy drop;
        oifname "${iface}" accept comment "Output through the VPN tunnel"
        oifname "lo" accept comment "Output to internal loopback"
        ip daddr { ${lan_networks} } accept comment "Output to the LAN"
        ip6 daddr { fe80::/10, fc00::/7, ff00::/8${lan6_networks:+, ${lan6_networks}} } accept comment "Output to the LAN over IPv6"
        udp dport ${wg_port} accept comment "WireGuard handshake to the VPN endpoint"
        udp dport { 67, 68 } accept comment "DHCP"
    }
}
EOF
}

__main() {
    local iface='proton'
    local user="${SUDO_USER:-${USER}}"
    local dry_run='false'
    local cfg_src=''
    ## RFC1918 by default: keep the LAN, docker bridges and the router reachable
    local lan_networks='192.168.0.0/16,172.16.0.0/12,10.0.0.0/8'
    ## IPv6 LANs are routinely globally addressed (any ISP handing out a /64), so
    ## link local and ULA are not enough: without the real prefix the kill switch
    ## drops replies to LAN clients over IPv6. Detected unless given explicitly.
    local lan6_networks=''

    while [ "${#}" -gt 0 ]; do
        case "${1}" in
        --iface)
            iface="${2}"
            shift 2
            ;;
        --user)
            user="${2}"
            shift 2
            ;;
        --lan)
            lan_networks="${2}"
            shift 2
            ;;
        --lan6)
            lan6_networks="${2}"
            shift 2
            ;;
        --dry-run)
            dry_run='true'
            shift
            ;;
        -h | --help)
            _print_usage
            return 0
            ;;
        -*) _err "unknown option '${1}'" ;;
        *)
            cfg_src="${1}"
            shift
            ;;
        esac
    done

    if [ "${cfg_src}" = '' ]; then
        _print_usage
        echo ''
        _print_prereqs
        echo ''
        _print_where_to_get_a_config | sed "s|SCRIPT_PATH|${0}|"
        _err 'no config given'
    fi
    if [ ! -f "${cfg_src}" ]; then
        echo >&2 "ERROR: no such file '${cfg_src}'"
        _print_where_to_get_a_config | sed "s|SCRIPT_PATH|${0}|" >&2
        exit 1
    fi
    if ! grep -q '^\[Peer\]' "${cfg_src}" || ! grep -q '^Endpoint' "${cfg_src}"; then
        echo >&2 "ERROR: '${cfg_src}' is not a WireGuard config (no [Peer]/Endpoint)"
        _print_where_to_get_a_config | sed "s|SCRIPT_PATH|${0}|" >&2
        exit 1
    fi
    ## wg-quick names the interface after the file, and Linux caps that at 15 chars
    [ "${#iface}" -le 15 ] || _err "iface '${iface}' is longer than 15 chars"

    if [ "${dry_run}" = 'false' ] && [ "$(id -u)" != '0' ]; then
        _err 'must run as root (or pass --dry-run to preview)'
    fi

    _check_prereqs

    ##########
    ## Config

    ## The kill switch has to let the handshake out, so it needs the endpoint port
    local wg_port=''
    wg_port="$(grep -oP '^Endpoint\s*=.*:\K\d+' "${cfg_src}" | head -1)"
    [ "${wg_port}" != '' ] || _err "could not read the endpoint port from '${cfg_src}'"

    if [ "${lan6_networks}" = '' ]; then
        lan6_networks="$(_detect_lan6_networks)"
        [ "${lan6_networks}" = '' ] || echo "INFO: detected LAN IPv6 prefixes: ${lan6_networks}"
    fi

    local dns_servers=''
    dns_servers="$(grep -oP '^DNS\s*=\s*\K.*' "${cfg_src}" | tr ',' ' ' | tr -s ' ')"

    local cfg_out=''
    cfg_out="$(mktemp)"
    # shellcheck disable=SC2064  # expand now, the temp file name is fixed
    trap "rm -f '${cfg_out}'" EXIT

    ## wg-quick implements `DNS =` by shelling out to `resolvconf`, which
    ## systemd-resolved systems do not ship. Where that is the case, rewrite the line
    ## into resolvectl hooks; the `~.` routing domain sends every lookup to Proton's
    ## resolver rather than only tunnel suffixes. Leaving DNS unset is not an option
    ## worth defaulting to: it resolves through the LAN while the tunnel is up.
    cp "${cfg_src}" "${cfg_out}"
    if [ "${dns_servers}" != '' ]; then
        if command -v resolvconf >/dev/null 2>&1; then
            echo 'INFO: resolvconf present, leaving the DNS line for wg-quick to handle'
        elif command -v resolvectl >/dev/null 2>&1; then
            sed -i -E '/^DNS\s*=/d' "${cfg_out}"
            sed -i "/^\[Interface\]/a PostUp = resolvectl dns %i ${dns_servers}; resolvectl domain %i '~.'" "${cfg_out}"
            sed -i "/^\[Interface\]/a PostDown = resolvectl revert %i" "${cfg_out}"
            echo 'INFO: rewrote the DNS line into resolvectl hooks'
        else
            _err 'neither resolvconf nor resolvectl found; install openresolv (or use
systemd-resolved), otherwise wg-quick cannot apply the VPN DNS and lookups leak'
        fi
    fi

    if [ "${dry_run}" = 'true' ]; then
        echo "INFO: would install as /etc/wireguard/${iface}.conf:"
        sed -E 's/^(PrivateKey|PublicKey)(\s*=).*/\1\2 <REDACTED>/' "${cfg_out}" | sed 's/^/    /'
        echo
        echo "INFO: would install /etc/vpn-py/killswitch.nft:"
        _killswitch_ruleset "${iface}" "${lan_networks}" "${wg_port}" "${lan6_networks}" | sed 's/^/    /'
        echo "INFO: would install /etc/sudoers.d/vpn-py for user '${user}'"
        return 0
    fi

    install -d -m 0700 -o root -g root /etc/wireguard
    install -m 0600 -o root -g root "${cfg_out}" "/etc/wireguard/${iface}.conf"
    echo "INFO: installed /etc/wireguard/${iface}.conf"

    ##########
    ## Killswitch ruleset

    install -d -m 0755 -o root -g root /etc/vpn-py
    _killswitch_ruleset "${iface}" "${lan_networks}" "${wg_port}" "${lan6_networks}" >/tmp/vpn-py-killswitch.nft
    nft -c -f /tmp/vpn-py-killswitch.nft || {
        rm -f /tmp/vpn-py-killswitch.nft
        _err 'generated nftables ruleset failed validation, nothing installed'
    }
    install -m 0644 -o root -g root /tmp/vpn-py-killswitch.nft /etc/vpn-py/killswitch.nft
    rm -f /tmp/vpn-py-killswitch.nft
    echo 'INFO: installed /etc/vpn-py/killswitch.nft'

    ##########
    ## Sudoers
    ##
    ## vpn.py runs `sudo -n`, so without this the cron job dies on the password
    ## prompt. Every entry is an exact command over a root owned path - no wildcards
    ## and no `nft -f -` reading a ruleset off stdin - so this grants the ability to
    ## run this tunnel and this kill switch, and nothing else.

    ## sudoers matches on the absolute path as invoked, and distros disagree about
    ## where these live (nft is /usr/sbin here, /usr/bin elsewhere), so resolve them
    ## rather than hardcoding. A wrong path here fails as a password prompt at 3am.
    local bin_wg_quick=''
    local bin_wg=''
    local bin_nft=''
    bin_wg_quick="$(command -v wg-quick)" || _err 'wg-quick not found (install wireguard-tools)'
    bin_wg="$(command -v wg)" || _err 'wg not found (install wireguard-tools)'
    bin_nft="$(command -v nft)" || _err 'nft not found (install nftables)'

    local sudoers_out=''
    sudoers_out="$(mktemp)"
    cat >"${sudoers_out}" <<EOF
## Installed by setup-protonvpn-host.sh for vpn.py --vpn protonvpn
${user} ALL=(root) NOPASSWD: ${bin_wg_quick} up ${iface}
${user} ALL=(root) NOPASSWD: ${bin_wg_quick} down ${iface}
${user} ALL=(root) NOPASSWD: ${bin_wg} show ${iface} *
${user} ALL=(root) NOPASSWD: ${bin_nft} -f /etc/vpn-py/killswitch.nft
${user} ALL=(root) NOPASSWD: ${bin_nft} list table inet vpn-killswitch
${user} ALL=(root) NOPASSWD: ${bin_nft} delete table inet vpn-killswitch
EOF

    ## Never install an unparsable sudoers file; a bad one breaks sudo entirely
    visudo -c -f "${sudoers_out}" >/dev/null || {
        rm -f "${sudoers_out}"
        _err 'generated sudoers file failed validation, nothing installed'
    }
    install -m 0440 -o root -g root "${sudoers_out}" /etc/sudoers.d/vpn-py
    rm -f "${sudoers_out}"
    echo "INFO: installed /etc/sudoers.d/vpn-py for user '${user}'"

    ##########
    ## State file
    ##
    ## vpn.py reads this to know whether this host has been set up, and for which
    ## interface and user. It lives outside /etc/wireguard deliberately: that
    ## directory is 0700 root, so an unprivileged vpn.py cannot even stat the config
    ## to tell "not set up" apart from "not allowed to look".

    local state_out=''
    state_out="$(mktemp)"
    cat >"${state_out}" <<EOF
{
  "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "user": "${user}",
  "iface": "${iface}",
  "wg_config": "/etc/wireguard/${iface}.conf",
  "killswitch_ruleset": "/etc/vpn-py/killswitch.nft",
  "lan_networks": "${lan_networks}",
  "lan6_networks": "${lan6_networks}",
  "source_config": "${cfg_src}"
}
EOF
    install -m 0644 -o root -g root "${state_out}" /etc/vpn-py/setup.json
    rm -f "${state_out}"
    echo 'INFO: recorded setup state in /etc/vpn-py/setup.json'

    ##########
    ## Verify

    ## Prove the grant works as the target user rather than assuming. vpn.py invokes
    ## `sudo -n nft ...` by bare name, so sudo resolves it through secure_path; if that
    ## finds a different binary than the one granted above, sudo asks for a password
    ## and the cron job fails silently. Listing a table that may not exist yet is fine
    ## here - what is being tested is whether sudo prompts, not the table.
    local verify_out=''
    verify_out="$(sudo -n -u "${user}" sudo -n nft list table inet vpn-killswitch 2>&1)"
    if printf '%s' "${verify_out}" | grep -qi 'password'; then
        echo "WARNING: '${user}' still gets a password prompt for nft. Check that"
        echo "WARNING: secure_path in /etc/sudoers covers $(dirname "${bin_nft}")"
        echo "WARNING: and $(dirname "${bin_wg_quick}"), and that they resolve to the"
        echo "WARNING: same binaries granted in /etc/sudoers.d/vpn-py"
    else
        echo "INFO: verified '${user}' can run the granted commands without a password"
    fi

    echo "INFO: next: vpn.py --status, then vpn.py --connect"
}

__main "${@}"
