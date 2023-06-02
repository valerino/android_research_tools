#!/usr/bin/env bash
source "$(dirname $(realpath $0))/shared.sh"

function usage {
    echo "get /proc/pid/maps giving a process/package name."
    echo "usage: $0 <-p process/package_name> [-d device serial] [-o to get pid only]"
}

while getopts "d:op:" arg; do
    case $arg in
    o)
        _PIDONLY=1
        ;;
    p)
        _PACKAGE="${OPTARG}"
        ;;
    d)
        _DEVICE="${OPTARG}"
        ;;
    *)
        usage "$0"
        exit 1
        ;;
    esac
done

if [ -z "$_PACKAGE" ]; then
    usage "$0"
    exit 1
fi

if [ ! -z "$_DEVICE" ]; then
    echo "target device=$_DEVICE"
fi

_res=$(run_adb shell su -c pidof "$_PACKAGE")
_r="$?"
echo "$_res"
if [ "$_r" -eq 1 ]; then
    echo "ERROR!"
    exit 1
fi
if [ ! -z "$_PIDONLY" ]; then
    exit 0
fi

_pid=$(get_result_from_lfs_string "$_res" 1)
run_adb shell su -c "cat /proc/$_pid/maps"
