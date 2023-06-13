rpc.exports = {
    run: script_main,
}

function trace_java_method(js_params) {
    var result_regex_filter = js_params.result_regex_filter
    var result_str_filter = js_params.result_str_filter
    var backtrace = js_params.backtrace
    var result_num_filter = js_params.result_num_filter
    var classmethod = js_params.method

    var delim = classmethod.lastIndexOf(".");
    if (delim === -1) {
        console.log('ERROR, wrong "method"=' + classmethod)
        return;
    }

    var target_class = classmethod.slice(0, delim)
    var target_method = classmethod.slice(delim + 1, classmethod.length)
    var hook = null
    var classLoaders = Java.enumerateClassLoadersSync()
    for (const loader of classLoaders) {
        try {
            loader.findClass(target_class);
            var classFactory = Java.ClassFactory.get(loader);
            hook = classFactory.use(target_class);
        } catch (error) {
            console.log(error + ", trying next classloader if any ...")
            continue
        }

        var overloadCount = hook[target_method].overloads.length;
        console.log("tracing " + classmethod + " [" + overloadCount + " overload(s)]");
        for (var i = 0; i < overloadCount; i++) {
            hook[target_method].overloads[i].implementation = function () {
                let bt = null
                if (backtrace) {
                    // get  backtrace
                    bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                }

                // get result
                var retval = this[target_method].apply(this, arguments);

                // filter
                try {
                    if (result_num_filter) {
                        if (retval.toString() != result_num_filter.toString()) {
                            return retval
                        }
                    }
                    if (result_str_filter) {
                        if (retval.toString().toLowerCase().indexOf(result_str_filter.toString().toLowerCase()) == -1) {
                            return retval
                        }
                    }
                    if (result_regex_filter) {
                        var re = new RegExp(result_regex_filter)
                        var filter_res = re.test(retval)
                        if (!filter_res) {
                            return retval
                        }
                    }
                }
                catch (ex) {

                }

                console.log('--------' + classmethod + ' called !---------------')
                if (backtrace) {
                    // print backtrace
                    console.log(classmethod + " backtrace:\n" + bt);
                }

                // print args
                console.log(classmethod + ' num arguments=' + arguments.length);
                if (arguments.length > 0) {
                    for (var j = 0; j < arguments.length; j++) {
                        
                        console.log(classmethod + " arg[" + j + "], type=" + typeof (arguments[j]) + ", val=" + arguments[j]);
                    }
                }

                // print retval            
                console.log(classmethod + " retval type=" + typeof (retval) + ", val=" + retval);
                console.log('\n')
                return retval;
            }
        }

        // done
        break
    }
}

function script_main(params) {
    const js_params = JSON.parse(params)
    console.log('script run() parameters=' + JSON.stringify(js_params))
    Java.perform(function () {
        trace_java_method(js_params)
    })
}
