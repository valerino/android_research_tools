#!/usr/bin/env bash
function usage {
  echo "run lldb-server on connected(USB) android device and starts debugging session."
  echo "usage: $0 [usb device id]"
  echo "env vars:"
  echo "    _LLDB_SERVER_PATH (path to android lldb-server to push on device, default=\"$HOME/Library/Android/sdk/ndk/25.1.8937393/toolchains/llvm/prebuilt/darwin-x86_64/lib64/clang/14.0.6/lib/linux/aarch64/lldb-server\")"
  echo "    _LLDB_PATH (lldb client, default=\"lldb\")"
  echo "    _LLDB_PORT (lldb port, will be forwarded from adb to localhost, default=8086)"
  echo "    _LLDB_INIT_SCRIPT (lldb init scripts, default=\"./lldb_init.txt\")"
}

function run_adb {
  _tmp=("$@")

  set -- "adb"
  if [ ! -z "$_DEVICE" ]; then
    set -- "$@" -s "$_DEVICE"
    export ANDROID_SERIAL=$_DEVICE
  fi

  for _i in "${_tmp[@]}"; do
    set -- "$@" "$_i"
  done

  echo "running $@ ..."
  "$@"
}

while getopts "d:" arg; do
  case $arg in
  d)
    _DEVICE="${OPTARG}"
    ;;
  *)
    usage "$0"
    exit 1
    ;;
  esac
done

if [ ! -z "$_DEVICE" ]; then
  echo "target device=$_DEVICE"
fi

# init defaults
if [ -z "$_LLDB_SERVER_PATH" ]; then
  _LLDB_SERVER_PATH="$HOME/Library/Android/sdk/ndk/25.1.8937393/toolchains/llvm/prebuilt/darwin-x86_64/lib64/clang/14.0.6/lib/linux/aarch64/lldb-server"
fi
if [ -z "$_LLDB_PATH" ]; then
  _LLDB_PATH="lldb"
fi
if [ -z "$_LLDB_PORT" ]; then
  _LLDB_PORT="8086"
fi
if [ -z "$_LLDB_INIT_SCRIPT" ]; then
  _LLDB_INIT_SCRIPT="./lldb_init.txt"
fi

echo "_LLDB_SERVER_PATH=$_LLDB_SERVER_PATH"
echo "_LLDB_PATH=$_LLDB_PATH"
echo "_LLDB_PORT=$_LLDB_PORT"
echo "_LLDB_INIT_SCRIPT=$_LLDB_INIT_SCRIPT"

run_adb shell su -c "pkill -9 lldb-server; rm /data/local/tmp/lldb-server"

echo "copying lldb-server to /data/local/tmp ..."
run_adb push "$_LLDB_SERVER_PATH" /data/local/tmp/lldb-server
if [ "$?" != 0 ]; then
  exit 1
fi

echo "forward port $_LLDB_PORT from adb ..."
run_adb kill-server
run_adb start-server
run_adb forward tcp:$_LLDB_PORT tcp:$_LLDB_PORT
if [ "$?" != 0 ]; then
  exit 1
fi

echo "starting remote lldb on device ..."
run_adb shell su -c "chmod 755 /data/local/tmp/lldb-server"
run_adb shell su -c "/data/local/tmp/lldb-server platform --listen \"*:$_LLDB_PORT\" --server" &
sleep 2

echo "starting $_LLDB -s $_LLDB_INIT_SCRIPT ..."
$_LLDB_PATH -s "$_LLDB_INIT_SCRIPT"

# platform select remote-android
# platform connect connect://:8086
# memory read 6e47b52690 --format Y --count 64