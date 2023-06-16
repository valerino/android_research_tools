rpc.exports = {
    run: script_main,
}
var _num_hits = 0

function trace_java_method(js_params) {
    var options = js_params['options']
    if (options == null) {
        options = JSON.parse('{}')
    }

    var result_regex_filter = options.result_regex_filter
    var result_str_filter = options.result_str_filter
    var print_stacktrace = options.print_stacktrace
    var print_parameters = options.print_parameters
    var print_result = options.print_result
    var detach_after_first_hit = options.detach_after_first_hit
    var result_num_filter = options.result_num_filter
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
                /**
                 * we're in the hooked function/overload here
                 */
                let bt = null
                if (print_stacktrace) {
                    // get stacktrace
                    bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new("(dummy exception)"));
                }

                // get result
                var retval = this[target_method].apply(this, arguments);
                if (detach_after_first_hit && _num_hits > 0) {
                    return retval
                }
                _num_hits += 1

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
                if (print_stacktrace) {
                    // print stacktrace
                    console.log(classmethod + " stacktrace:\n" + bt);
                }

                if (print_parameters) {
                    // print args
                    console.log(classmethod + ' num arguments=' + arguments.length);
                    if (arguments.length > 0) {
                        for (var j = 0; j < arguments.length; j++) {

                            console.log(classmethod + " arg[" + j + "], type=" + typeof (arguments[j]) + ", val=" + arguments[j]);
                        }
                    }
                }

                if (print_result) {
                    // print retval            
                    console.log(classmethod + " retval type=" + typeof (retval) + ", val=" + retval);
                    console.log('\n')
                }

                if (detach_after_first_hit) {
                    send("detach")
                }

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
