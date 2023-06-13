# android research useful tools

- [frida_run_script.py](./frida_run_script.py): useful tool to inject a frida script, supports multiple connected devices.

  - [frida_get_address.js](./frida_get_address.js): simple script to inject, get pid, module base, function address providing *name* or *offset*.
  
    ~~~bash
    ./frida_run_script.py --device R58NC03HG5E --package_name com.whatsapp --js_path ./frida_get_address.js --parameters '{"module": "libwhatsapp.so", "offset": "0x48d198"}'
    ~~~
  
  - [android_get_address.sh](./android_get_address.sh): shortcut for *frida_run_script.py* + *frida_get_address.js*

    ~~~bash
    export _DEVICE=037AYV1WBW
    export _PROCESS="com.whatsapp"
    export _MODULE="libwhatsapp.so"
    export _DEVICE="$_CALLER"
    ./tools/android_get_address.sh -a 0x6b6998 
    ~~~

  - [frida_dump_registers.js](./frida_dump_registers.js): dumps registers and memory when frida function hook triggers.
  
    ~~~bash
    ./tools/frida_run_script.py --package_name com.whatsapp --js_path ./tools/frida_dump_registers.js --parameters ./tools/dump_registers_cfg.json --device $_CALLER
    ~~~

    an example of dump_registers_cfg.json:

    ~~~js
    {
        "module": "libwhatsapp.so",
        // hook point, can be offset or export name
        "offset": "0x447b48",
        "options": {
            "dump_memory_size": 256,
            "detach_after_first_hit": true,
            // print full context
            "print_context": false,
            // print stacktrace
            "print_stacktrace": false
        },
        "registers": {
            // put any register here, it is shown if the key is in frida this.context
            "x0": {
                // show memory at $x0
                "show_memory_at": true,
                // show memory at *$x0
                "show_memory_at_deref": true
                // show memory at **$x0
                "show_memory_at_deref_deref": true
            },
            "x1": {
                "show_memory_at": true
            }
        },
        "offsets": {
            // offset from base address
            "0x8d0a50": {
                "show_memory_at": true
                "show_memory_at_deref": true
            }
        }
    }    
    ~~~

  - [frida_dump_java_method.js](./frida_dump_java_method.js): dump java method with arguments and possibly backtrace and result filtering.

    ~~~bash
    ./tools/frida_run_script.py --device 037AYV1WBW --package_name com.whatsapp --js_path ./tools/frida_dump_java_method.js --parameters '{"method": "com.whatsapp.protocol.VoipStanzaChildNode.toProtocolTreeNode", "result_regex_filter": "^<offer"}'
    ~~~

    supported parameters:

    ~~~js
    {
        "method": "method name as package.methodname use $init as methodname for constructor",
        "backtrace": true to print backtrace,
        "result_regex_filter": "a_regex to match",
        "result_num_filter": a_number, method result will be converted to string and compared,
        "result_str_filter": a substring, method result will be lowercased and indexOf() called on it
    }
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
