#!/bin/bash
# Query effective configuration only; do not start any daemon.
set -euo pipefail
package=${1:?Usage: test-mac-effective-config.sh ADDON_PACKAGE}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
bsdtar -xf "$package" -C "$work"
mkdir -p "$work/etc/NetworkManager/conf.d" "$work/var/lib/NetworkManager" "$work/etc/systemd/system" "$work/etc/modprobe.d"
printf '[main]\n' >"$work/etc/NetworkManager/NetworkManager.conf"
nm_config() {
  NetworkManager --print-config --config="$work/etc/NetworkManager/NetworkManager.conf" \
    --config-dir="$work/etc/NetworkManager/conf.d" --system-config-dir="$work/usr/lib/NetworkManager/conf.d" \
    --intern-config="$work/var/lib/NetworkManager/intern.conf"
}
nm_config >"$work/network.conf"
grep -Fxq 'wifi.backend=iwd' "$work/network.conf"
printf '[device]\nwifi.backend=wpa_supplicant\n' >"$work/etc/NetworkManager/conf.d/20-omarchy-mac-wifi.conf"
nm_config >"$work/network.conf"
grep -Fxq 'wifi.backend=wpa_supplicant' "$work/network.conf"
! grep -Fxq 'wifi.backend=iwd' "$work/network.conf"
# systemd's own configuration search reports a vendor fragment, then its
# administrator replacement and drop-ins. The runtime tests cover masks.
systemd-analyze --root="$work" cat-config systemd/system/omarchy-wifi-resume-fix.service >"$work/unit.conf"
grep -Fxq 'ExecStart=/usr/bin/omarchy-wifi-resume-fix' "$work/unit.conf"
printf '[Service]\nExecStart=/administrator/helper\n' >"$work/etc/systemd/system/omarchy-wifi-resume-fix.service"
systemd-analyze --root="$work" cat-config systemd/system/omarchy-wifi-resume-fix.service >"$work/unit.conf"
grep -Fxq 'ExecStart=/administrator/helper' "$work/unit.conf"
! grep -Fxq 'ExecStart=/usr/bin/omarchy-wifi-resume-fix' "$work/unit.conf"
# modprobe honors an administrator-supplied same-name file. Its explicit
# configuration directory avoids reading or changing the host's settings.
modprobe --config="$work/usr/lib/modprobe.d" --showconfig | grep -Fx 'options appledrm show_notch=1'
printf 'options appledrm show_notch=0\n' >"$work/etc/modprobe.d/asahi-notch.conf"
modprobe --config="$work/etc/modprobe.d" --showconfig | grep -Fx 'options appledrm show_notch=0'
echo 'ok - effective NetworkManager and systemd overrides; module defaults parse'
