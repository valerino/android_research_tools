import json
import logging
import subprocess
import sys
import time

import frida
from frida.core import Device
from py3adb import ADB

_logger = logging.getLogger()

_adb = ADB('adb')


def frida_server_install(path: str):
    """install the given frida-server on the (rooted) connected device, through adb. 
    NOTE: frida-server is installed in /data/local/tmp/frida-server

    Args:
        path (str): _description_
    """
    _logger.info('installing frida-server ...')
    process_kill('frida-server')
    _adb.shell_command(
        'su -c "rm /data/local/tmp/frida-server"')
    _adb.push_local_file(path, "/data/local/tmp/frida-server")
    _adb.shell_command('su -c "chmod 755 /data/local/tmp/frida-server"')


def frida_server_run(restart: bool = False):
    """runs frida-server on the connected device, through adb. 
    NOTE: frida-server must be in /data/local/tmp/frida-server and the device must be rooted.

    Args:
        restart (str): _description_
    Raises:
        Exception: _description_
    """
    which_res = _adb.shell_command(
        'su -c "which /data/local/tmp/frida-server"')
    if which_res is None:
        raise Exception(
            '/data/local/tmp/frida-server not found, relaunch with --frida_server_path to install frida-server from local!')

    running = _adb.shell_command('ps -A | grep frida-server')
    if running is not None:
        _logger.info('frida-server already running!')
        if restart:
            process_kill('frida-server')
        else:
            return

    _logger.info('running frida-server ...')
    _adb.shell_command(
        'su -c "/data/local/tmp/frida-server -D" &')


def frida_get_session(package_name: str, dev: str = None) -> frida.core.Session:
    """attach frida to the given (running on the connected usb device) package name

    Args:
        package_name (str): _description_
        dev(str): _description_

    Raises:
        Exception: _description_

    Returns:
        frida.core.Session: _description_
    """
    if dev is not None:
        _logger.info('using device=%s for frida session ...' % (dev))

    dev: Device = frida.get_device(id=dev)
    apps = dev.enumerate_applications()
    session = None
    for a in apps:
        if a.identifier == package_name:
            # attach to pid
            _logger.info('attaching to package=%s, pid=%d ...' %
                         (a.identifier, a.pid))
            session = dev.attach(a.pid)
            return session

    raise Exception('cannot attach to package=%s' % (package_name))


def frida_cleanup(session: frida.core.Session, script: frida.core.Script):
    """unload script and cleanup frida session

    Args:
        session (frida.core.Session): _description_
        script (frida.core.Script): _description_
    """
    if script is not None:
        _logger.info('unloading script ...')
        script.unload()
    if session is not None:
        _logger.info('detaching session ...')
        session.detach()


def frida_load_script(session: frida.core.Session, path: str, handlers: list = None, params: dict = None) -> frida.core.Script:
    """loads a js script from file in frida

    Args:
        session (frida.core.Session): _description_
        path (str): _description_
        handlers (list): optional list of tuples as [("handler_name", handler_func), ...]
        params (dict): optional json string with parameters for the script (must have a run(json_str) function exported!)

    Returns:
        frida.core.Script: _description_
    """
    _logger.info('reading script at %s ...' % (path))
    with open(path, 'r') as f:
        scr = f.read()

    _logger.info('loading script ...')
    the_script = session.create_script(scr)
    if handlers is not None:
        for h in handlers:
            # h[0] = name
            # h[1] = callback
            _logger.info('installing %s handler=%s ...' % (h[0], h[1]))
            the_script.on(h[0], h[1])

    the_script.load()
    if params is not None:
        _logger.info('getting script exports ...')
        exports = the_script.list_exports_sync()
        if 'run' not in exports:
            raise Exception(
                'script must have run(params) exported function, where params is a json dict!')

        # call run with params!
        api = the_script.exports_sync
        _logger.info('calling script run() ...')
        api.run(params)

    return the_script


def process_kill(package_name: str):
    """kills a process by specyfing the package name, if it is running.

    Args:
        package_name (str): _description_
    """
    _logger.info('killing %s ...' % package_name)
    _adb.shell_command(
        'su -c "pkill -9 %s"' % (package_name))


def adb_init_device(dev: str = None):
    """sets the target device string for ADB, or None to use the (single) plugged device

    Args:
        dev (str): _description_
    """
    res, l = _adb.get_devices()
    if res != 0:
        raise Exception('no device plugged!')
    if len(l) == 1:
        # only 1 device plugged
        return
    if len(l) > 1 and dev is None:
        raise Exception('multiple devices plugged(%s) !' % (l))

    if dev in l or dev.upper() in l:
        _logger.info('setting target adb device to %s ...' % (dev))
        _adb.set_target_device(dev)
    else:
        raise Exception('device %s not found!' % (dev))


def adb_logcat(package_name: str = None, device: str = None):
    """gets adb logcat output to stdout, runs until interrupted. do not uses py3adb.

    Args:
        package_name (str, optional): _description_. Defaults to None.
        device (str, optional): _description_. Defaults to None.

    Raises:
        Exception: _description_
    """

    #  shell 'logcat --pid=$(pidof -s "$_PACKAGE")'

    ar = ['adb']
    if device is not None:
        ar.append('-s')
        ar.append(device)
    ar.append('logcat')
    if package_name is not None:
        res = _adb.shell_command('pidof %s' % (package_name))
        if res is None:
            raise Exception('%s not found/running!' % (package_name))

        ar.append('--pid')
        ar.append(res[0])

    _logger.info('running: %s ...' % (ar))
    subprocess.run(ar, stderr=sys.stderr, stdout=sys.stdout, check=False)


def app_run(package_name: str):
    """runs an app (only if not yet running) specifying the package name.

    Args:
        package_name (str): _description_
    """
    is_running = _adb.shell_command(
        'su -c "ps -A | grep %s"' % (package_name))
    if is_running is not None:
        _logger.info('%s already running ...' % (package_name))
        return

    # run
    _logger.info('running %s ...' % (package_name))
    res = _adb.shell_command(
        'monkey -p %s 1' % (package_name))
    if res is None:
        raise Exception('cannot run %s !' % (package_name))

    time.sleep(2)
