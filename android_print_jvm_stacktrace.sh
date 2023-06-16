#!/usr/bin/env bash
source "$(dirname $(realpath $0))/shared.sh"

function usage {
    echo "print JVM stacktrace of method in the given package."
    echo "usage: $0 <-p package> <-m method> [-d device serial] [-r to restart frida-server] [-f detach after first hit]"
    echo "-p, -m, -d can also be defined as _PROCESS, _MODULE, _DEVICE environment variables, respectively."
}

_DETACH_AFTER_FIRST="false"

while getopts "p:m:d:rf" arg; do
    case $arg in
    f)
        _DETACH_AFTER_FIRST="true"
        ;;
    p)
        _PROCESS="${OPTARG}"
        ;;
    m)
        _METHOD="${OPTARG}"
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

if [ -z "$_METHOD" ] || [ -z "$_PROCESS" ]; then
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

set -- "$@" --package_name "$_PROCESS" --js_path "$(get_absolute_script_parent_path)/frida_dump_java_method.js"
_PARAMS="{\"method\":\"$_METHOD\", \"options\": { \"print_stacktrace\": true, \"detach_after_first_hit\": "$_DETACH_AFTER_FIRST" } }"
set -- "$@" --parameters
set -- "$@" "$_PARAMS"
echo "running $@ ..."
"$@"
