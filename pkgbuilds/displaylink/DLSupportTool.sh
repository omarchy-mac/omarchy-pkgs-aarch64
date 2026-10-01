#!/usr/bin/env bash
# Copyright (c) 2024 DisplayLink (UK) Ltd.

OUTPUT_PREFIX="DLSupportTool_Output"

export LANG=C
export LC_ALL=C

print_help()
{
  cat << EOF
Usage: ${BASH_SOURCE[0]##*/} [-h | --help | --debug | --nodebug]

DisplayLink Support Tool for Linux.

options:
  -h, --help  show this help message and exit
  --debug     enable Advanced DisplayLink logging
  --nodebug   disable Advanced DisplayLink logging
EOF
}

main()
{
  case ${1-} in
    --debug)
      enable_advanced_logging
      ;;

    --nodebug)
      disable_advanced_logging
      ;;

    '')
      gather_logs
      ;;

    -h|--help)
      print_help
      ;;

    *)
      echo >&2 "Unknown argument \"$1\""
  esac
}

get_device_detail()
{
  local device=$1
  local detail=$2
  local full_path="/sys/bus/usb/devices/$device/$detail"
  if [[ -f $full_path ]]; then
    head -n1 "$full_path"
  fi
}

get_attached_dl_devices()
{
  find /sys/bus/usb/devices -maxdepth 1 -type d | while read -r dir; do
    local id_vendor_path=$dir/idVendor
    if [[ -f $id_vendor_path && $(head -n1 "$id_vendor_path") == '17e9' ]]; then
      basename "$dir"
    fi
  done
}

get_cpu_info()
{
  sed -En '/^model name[^:]*:[[:space:]]*/{s///;p;q;}' /proc/cpuinfo
  sed -n '/^cache size[^:]*/{s//Cache/;p;q;}' /proc/cpuinfo
  sed -n '/^cpu cores[^:]*/{s//Cores/;p;q;}' /proc/cpuinfo
}

get_memory_info()
{
  sed -En '/^MemTotal:[[:space:]]*/{s///;p;q;}' /proc/meminfo
}

get_dl_driver_version()
{
  local regex='v([[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+)'
  local dlm='/usr/lib/displaylink/DisplayLinkManager'
  if [[ ! -x $dlm ]]; then
    dlm='/opt/displaylink/DisplayLinkManager'
  fi
  if [[ $("$dlm" -version) =~ $regex ]]; then
    echo "${BASH_REMATCH[1]}"
  fi
}

get_loaded_dl_driver_version()
{
  head -n1 /sys/devices/evdi/version
}

get_libevdi_version()
{
  local libevdi='/opt/displaylink/libevdi.so'
  if [[ ! -e $libevdi ]]; then
    libevdi=/usr/lib/libevdi.so
  fi

  local real_name
  if real_name=$(readlink "$libevdi"); then
    echo "${real_name#*.so.}"
  else
    echo "?.?.?"
  fi
}

is_dlm_running()
{
  pgrep -x DisplayLinkManager
}

user_sessions()
{
  loginctl | awk "/$(logname)/ {print \$1}"
}

session_type()
{
  user_sessions | xargs loginctl show-session -p Type | tr \\n ' '
}

evdi_for_current_kernel()
{
  find /lib/modules/"$(uname -r)" -name "evdi*" | head -n1
}

screen_layout()
{
  xrandr -q | sed 's/^/  /'
}

get_platform()
{
  lsb_release -d | sed -En '/^Description:[[:space:]]*/{s///;p;q;}'
}

get_machine_info()
{
  echo -n "OS info: "
  get_platform
  echo

  echo -n "CPU info: "
  get_cpu_info | tr \\n ' '
  echo

  printf '\n%s' "Installed RAM: "
  get_memory_info
  echo

  echo -n "DL driver version: "
  get_dl_driver_version
  echo

  echo -n "EVDI kernel module version: "
  get_loaded_dl_driver_version
  echo

  echo -n "EVDI kernel module file location: "
  evdi_for_current_kernel
  echo

  echo "Screen layout according to xrandr:"
  screen_layout
  echo

  echo -n "Lib evdi module version: "
  get_libevdi_version
  echo

  echo -n "DLM running: "
  if is_dlm_running; then
    echo true
  else
    echo false
  fi

  echo -n "Session info (x11/wayland): "
  session_type
  echo

  get_attached_dl_devices | while read -r device; do
    printf 'DL device connected: Bus %03d, Device %03d, ID 17e9:%s\n' \
      "$(get_device_detail "$device" busnum)" \
      "$(get_device_detail "$device" devnum)" \
      "$(get_device_detail "$device" idProduct)"

    printf 'Name: %s\n' "$(get_device_detail "$device" product)"
    printf 'Speed: %s Mbps\n' "$(get_device_detail "$device" speed)"
  done
}

save_machine_info()
{
  get_machine_info | sed '/^$/d' > machine_info.txt
}

find_and_copy()
{
  local dir=$1
  local pattern=$2
  local dest=${3:-.}
  [[ -d $dir ]] || return 0
  find "$dir" -maxdepth 1 -type f -name "$pattern" -exec cp '{}' "$dest" \;
}

save_files()
{
  mkdir xorg{-user,} displaylink crashes

  cp /proc/cpuinfo .
  cp /proc/meminfo .
  find_and_copy /var/crash '*DisplayLinkManager*.crash' crashes
  find_and_copy /var/log 'Xorg.*' xorg
  find_and_copy "/home/$(logname)/.local/share/xorg" 'Xorg.*' xorg-user
  find_and_copy /var/log/displaylink '*' displaylink

  find . -type f -name '.*' | while read -r file; do
    # the directory either exist or this loop will not execute
    # shellcheck disable=SC2164
    cd "$(dirname "$file")"
    file=$(basename "$file")
    mv "$file" "${file#.}"
  done

  find . -type d -empty -delete
}

save_processes_output()
{
  dmesg > dmesg.txt
  dmidecode > dmidecode.txt
  ps -aux > ps_aux.txt
  uptime > uptime.txt
  journalctl /usr/bin/gnome-shell > gnome_shell.txt
  journalctl -k -b -1 > dmesg_previous.txt
  lsmod > lsmod.txt

  if command -v lsusb >/dev/null; then
    lsusb | tee lsusb.txt | while read -r device; do
      if [[ $device =~ 17e9:[[:alnum:]]{4} ]]; then
        device=${BASH_REMATCH[0]}
        lsusb -v -d "$device" > "lsusb_${device//:/_}.txt"
      fi
    done
  else
    echo >&2 "lsusb tool not found. Gathered logs will be incomplete."
  fi
}

save_deb_info()
{
  if command -v dpkg >/dev/null; then
    dpkg -l | grep -F -e evdi -e displaylink-driver > dpkg.txt
  fi
}

dl_xml()
{
  xmlstarlet "$@" /var/log/displaylink/.dl.xml
}

xml_delete_nodes()
{
  local {in,out}_path xpaths=()

  while [[ $# -gt 0 ]]; do
    in_path=${1##/}
    shift

    out_path=/${in_path%%/*}
    in_path=${in_path#*/}

    while [[ $in_path == */* ]]; do
      out_path+="/node[@name='${in_path%%/*}']"
      in_path=${in_path#*/}
    done

    out_path+="/node[@name='$in_path']"
    xpaths+=(-d "$out_path")
  done
  dl_xml edit -L "${xpaths[@]}"
}

xml_insert_node()
{
  local node_path=${1##/}
  local assigned_value=$2
  local current_node=${node_path%%/*}
  local xpath=/$current_node
  node_path=${node_path#*/}

  while [[ $node_path == */* ]]; do
    current_node=${node_path%%/*}
    xpath+="/node[@name='$current_node']"
    node_path=${node_path#*/}

    if [[ -z $(dl_xml sel -t -c "$xpath") ]]; then
      dl_xml edit -L -s "${xpath%/*}" -t elem -n node_new \
          -s "${xpath%[*}_new" -t attr -n name -v "$current_node" \
          -r "${xpath%[*}_new" -v node
    fi
  done

  dl_xml edit -L -d "$xpath/node[@name='$node_path']" \
      -s "$xpath" -t elem -n node_new -v "$assigned_value" \
      -s "$xpath/node_new" -t attr -n name -v "$node_path" \
      -r "$xpath/node_new" -v value
}

XML_DL_ROOT="/DL_HIVE/HKEY_LOCAL_MACHINE/Software/DisplayLink"

check_if_xmlstarlet_is_installed()
{
  if ! command -v xmlstarlet > /dev/null ; then
    echo >&2 "xmlstarlet is not installed."
    echo >&2 "It's required to use --debug and --nodebug options."
    exit 1
  fi
}

enable_advanced_logging()
{
  check_if_xmlstarlet_is_installed

  local dl_key_modules="$XML_DL_ROOT/DisplayLinkManager/Logger/Modules"
  xml_insert_node "$dl_key_modules/connBandwidth/verbosity"      WARN
  xml_insert_node "$dl_key_modules/default/Outputs/Log"          DEBUG
  xml_insert_node "$dl_key_modules/UpdateEngineStats/verbosity"  WARN
  xml_insert_node "$dl_key_modules/UpdateEngineThread/verbosity" WARN
  xml_insert_node "$dl_key_modules/DeviceWindow/verbosity"       WARN
  xml_insert_node "$dl_key_modules/LUsbConnAlex/verbosity"       WARN
  xml_insert_node "$dl_key_modules/LUsbConnFpga/verbosity"       WARN

  local dl_key_outputs="$XML_DL_ROOT/DisplayLinkManager/Logger/Outputs/Log"
  xml_insert_node "$dl_key_outputs/filename"   "/var/log/displaylink/DisplayLinkManager.log"
  xml_insert_node "$dl_key_outputs/line type"  "1"
  xml_insert_node "$dl_key_outputs/max size"   "500000"
  xml_insert_node "$dl_key_outputs/Mode"       "Decorate"

  xml_insert_node "$XML_DL_ROOT/Logger/verbosity"          "DEBUG"
  xml_insert_node "$XML_DL_ROOT/Core/EnableUniqueDmpFiles" "Yes"

  echo >&2 "Advanced DisplayLink Logging enabled."
  kill_dlm
}

disable_advanced_logging()
{
  check_if_xmlstarlet_is_installed

  xml_delete_nodes "$XML_DL_ROOT/DisplayLinkManager" \
                   "$XML_DL_ROOT/Logger" \
                   "$XML_DL_ROOT/Core"

  echo >&2 "Advanced DisplayLink Logging disabled."
  kill_dlm
}

kill_dlm()
{
  if killall -s SIGTERM DisplayLinkManager &>/dev/null; then
    echo >&2 "DisplayLinkManager should restart shortly."
  fi
}

gather_logs()
{
  local tmp_dir
  tmp_dir=$(mktemp -d) || exit

  local archive
  archive=$(pwd)
  archive+=/$OUTPUT_PREFIX
  archive+=$(date '+_%Y%m%d_%H%M')
  archive+=.tar.gz

  (
    # the directory is verified to exist at the start of the function
    # shellcheck disable=SC2164
    cd "$tmp_dir"
    save_machine_info
    save_deb_info
    save_files
    save_processes_output
    tar -czf "$archive" ./*
  )

  rm -rf "$tmp_dir"
  echo "Saved as $archive"
}

if [[ $(id -u) != "0" ]]; then
  echo >&2 "This script requires root/superuser privileges."
  exit 1
fi

main "$@"
