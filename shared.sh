function get_absolute_script_parent_path() {
    # get caller script parent path
    dirname $(realpath $0)
}

function get_result_from_lfs_string() {
    # split \n separated string, and get nth element
    # $1: \n separated strings
    # $2: nth elementh to get, 0 based
    IFS=$'\n' read -r -d '' -a _r <<<"$1"
    echo "${_r[$2]}"
}

function run_adb {
    # $1: commands vararg
    # _DEVICE must be set to the adb ANDROID_SERIAL (adb devices) to target a specific connected device

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
