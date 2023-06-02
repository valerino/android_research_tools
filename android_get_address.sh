#!/usr/bin/env bash
source "$(dirname $(realpath $0))/shared.sh"

function usage {
    echo "resolve offset or export in process, return address, pid, base"
    echo "usage: $0 <-p process> <-m modulename> <-a offset as 0xOFFSETFROMBASE|exportname> [-d device serial] [-r to restart frida-server]"
    echo "-p, -m, -d can also be defined as _PROCESS, _MODULE, _DEVICE environment variables, respectively."
}

while getopts "p:a:m:d:r" arg; do
    case $arg in
    p)
        _PROCESS="${OPTARG}"
        ;;
    a)
        _ADDRESS="${OPTARG}"
        ;;
    m)
        _MODULE="${OPTARG}"
        ;;
    d)
        _DEVICE="${OPTARG}"
        ;;
    r)
        _RESTART=1
        ;;
    *)
        usage "$0"
        exit 1
        ;;
    esac
done

if [ -z "$_MODULE" ] || [ -z "$_PROCESS" ] || [ -z "$_ADDRESS " ]; then
    usage "$0"
    exit 1
fi

set -- "$(get_absolute_script_parent_path)/frida_run_script.py"
if [ ! -z "$_DEVICE" ]; then
    set -- "$@" --device $_DEVICE
fi
if [ ! -z "$_RESTART" ]; then
    set -- "$@" --frida_restart
fi
set -- "$@" --package_name "$_PROCESS" --js_path "$(get_absolute_script_parent_path)/frida_get_address.js"
_PARAMS="{\"module\":\"$_MODULE\", \"offset\":\"$_ADDRESS\"}"
set -- "$@" --parameters
set -- "$@" "$_PARAMS"
echo "running $@ ..."
"$@"
