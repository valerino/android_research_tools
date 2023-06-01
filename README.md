# android research useful tools

- [frida_run_script.py](./frida_run_script.py): useful tool to inject a frida script, supports multiple connected devices.

  - [frida_get_address.js](./frida_get_address.js): simple script to inject, get pid, module base, function address providing *name* or *offset*.
  
    ~~~bash
    ./frida_run_script.py --device R58NC03HG5E --package_name com.whatsapp --js_path ./frida_get_address.js --parameters '{"module": "libwhatsapp.so", "offset": "0x48d198"}'
    ~~~

- [android_logcat.sh](./adb_logcat.py): runs *adb logcat* on the device, can filter for package name, supports multiple connected devices.

- [android_run_lldb.sh](./android_run_lldb.sh): connects to lldb-server on device, supports multiple connected devices. uses code from [lldb.sh](https://github.com/ihnorton/lldb.sh).

- [android_get_map.sh](./android_get_map.sh): get process map, supports multiple connected devices.

## vscode-lldb integration

> needs vscode-lldb extension

copy [remote_lldb_vscode](./remote_lldb_vscode.json) configuration as *.vscode/launch.json* in a workspace.

> the configuration must be edited (*pid* of the process to be attached). **multiple attached devices are not supported**.

run lldb-server on android

~~~bash
./android_run_lldb.sh -n
~~~

then run the debug configuration to attach to the desired process.
