var js_params = null
var base = null
rpc.exports = {
    run: script_main,
}

function dump_internal(addr, dump_size, node_options) {
    const show_mem = node_options['show_memory_at']
    const show_mem_at_deref = node_options['show_memory_at_deref']
    const show_mem_at_deref_deref = node_options['show_memory_at_deref_deref']
    if (show_mem) {
        try {
            console.log("dumping " + dump_size + " bytes at " + addr)
            const ar = Memory.readByteArray(addr, dump_size);
            console.log(ar)
            console.log('\n')
        }
        catch (ex) {
            console.log("ERROR: cannot read memory at " + addr)
        }
    }
    if (show_mem_at_deref) {
        let pointed_addr = null
        try {
            pointed_addr = addr.readPointer()
            console.log("dumping " + dump_size + " bytes at *" + addr + "=" + pointed_addr)
            const ar = Memory.readByteArray(pointed_addr, dump_size);
            console.log(ar)
        }
        catch (ex) {
            console.log("ERROR: cannot read memory at *" + addr + "=" + pointed_addr)
        }
    }
    if (show_mem_at_deref_deref) {
        let pointed_addr = null
        try {
            const pointed_addr = addr.readPointer().readPointer()
            console.log("dumping " + dump_size + " bytes at *" + addr + "=" + pointed_addr)
            const ar = Memory.readByteArray(pointed_addr, dump_size);
            console.log(ar)
        }
        catch (ex) {
            console.log("ERROR: cannot read memory at **" + addr + "=" + pointed_addr)
        }
    }
    console.log("\n")
}

function dump(context, base, registers, offsets, options) {
    const dump_size = options["dump_memory_size"]
    if (dump_size == null) {
        dump_size = 256
    }
    const print_all_registers = options["print_context"]
    if (print_all_registers) {
        console.log("--------------------------------------")
        console.log("context at PC=" + context.pc)
        console.log("--------------------------------------")
        console.log(JSON.stringify(context, null, '\t'))
    }
    if (registers) {
        const registers_keys = Object.keys(registers)
        for (let i = 0; i < registers_keys.length; i++) {
            const k = registers_keys[i]
            if (k in context) {
                console.log("--------------------------------------")
                console.log("dumping register " + k + "=" + context[k])
                console.log("--------------------------------------")
                const reg_addr = ptr(context[k])
                dump_internal(reg_addr, dump_size, registers[k])
            }
        }
    }
    if (offsets) {
        const offsets_keys = Object.keys(offsets)
        for (let i = 0; i < offsets_keys.length; i++) {
            const k = offsets_keys[i];
            const show_mem = offsets[k]['show_memory_at']
            const show_mem_at_deref = offsets[k]['show_memory_at_deref']
            const show_mem_at_deref_deref = offsets[k]['show_memory_at_deref_deref']
            const full_addr = base.add(parseInt(k, 16))
            console.log("--------------------------------------")
            console.log("dumping offset " + k + ", address=" + full_addr)
            console.log("--------------------------------------")
            dump_internal(full_addr, dump_size, offsets[k])
        }
    }
}

function script_main(params) {
    js_params = JSON.parse(params)
    console.log('script run() parameters=' + JSON.stringify(js_params))

    // find address
    base = Module.findBaseAddress(js_params.module)
    var addr = null
    if (js_params.offset && js_params.offset.startsWith('0x')) {
        const offset = parseInt(js_params.offset, 16)
        addr = base.add(offset)
    }
    else {
        addr = Process.findModuleByName(js_params.module).getExportByName(js_params.name)
    }
    var js = {
        "pid": Process.id,
        "module": js_params.module,
        "base": base,
        "address": addr
    }
    if (js_params.name) {
        js["name"] = js_params.name
    }
    console.log(JSON.stringify(js, null, '\t'))

    // hook
    Interceptor.attach(addr, {
        onEnter(args) {
            // dump registers
            dump(this.context, base, js_params['registers'], js_params['offsets'], js_params["options"])
            if (js_params["options"]) {
                if (js_params["options"]["detach_after_first_hit"]) {
                    send("detach")
                }
            }
        }
    })
}