
function script_main(params) {
    const p = JSON.parse(params)
    console.log('script run() parameters=' + JSON.stringify(p))
    const base = Module.findBaseAddress(p.module)
    var addr = null
    if (p.offset && p.offset.startsWith('0x')) {
        const offset = parseInt(p.offset, 16)
        addr = base.add(offset)
    }
    else {
        addr = Process.findModuleByName(p.module).getExportByName(p.name)
    }
    var js = {
        "pid": Process.id,
        "module": p.module,
        "base": base,
        "address": addr
    }
    if (p.name) {
        js["name"] = p.name
    }
    console.log(JSON.stringify(js, null, '\t'))
    send("detach")
}

rpc.exports = {
    run: script_main,
}

