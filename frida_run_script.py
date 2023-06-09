#!/usr/bin/env python3
import argparse
import json
import logging
import os
import sys
from time import sleep

import coloredlogs
import hook_utils.hook_utils as hook_utils

coloredlogs.install(level='INFO')
_logger = logging.getLogger()
_outfile = None
_detach_requested = False


def on_message(message, data):
    """on "message" handler

    Args:
        message (_type_): _description_
        data (_type_): _description_
    """

    global _outfile, _detach_requested
    # _logger.info('message=%s, data=%s' % (message, data))
    if message.get('payload', None) is not None:
        if message['payload'] == 'detach':
            _logger.warning('script requested detaching!')
            _detach_requested = True
            return

    if _outfile is not None and data is not None:
        # by default, if data is not None and _outfile is provided, write content to _outfile
        #  TODO: maybe change this in favor of proper command ...
        _outfile.write(data)


def main():
    parser = argparse.ArgumentParser(
        description='inject js in android process, trace api and get dump.')
    parser.add_argument('--package_name', nargs=1,
                        help='package name to attach to. it is ensured the package is running.')
    parser.add_argument('--kill', help='if set, --package_name is killed if running, and restarted prior to injection.',
                        action='store_const', const=True, default=False)
    parser.add_argument('--js_path', nargs=1,
                        help="script to be loaded.", required=True)
    parser.add_argument('--dump_out_path', nargs=1,
                        help="if set, dump data sent by script to the given file")
    parser.add_argument('--frida_restart', help='if set, if frida-server is already running it is restarted.',
                        action='store_const', const=True, default=False)
    parser.add_argument('--frida_server_path', nargs=1,
                        help='if set, tries to upload and run frida-server on the device.')
    parser.add_argument('--frida_force_reinstall',
                        help='if set and frida_server_path is set, force reinstall even if frida-server is already there (default=False).',
                        action='store_const', const=True, default=False)
    parser.add_argument('--device', nargs=1,
                        help="if set, use plugged device with the given serial.", default=[None])
    parser.add_argument('--parameters', nargs=1,
                        help="if set, JSON string, or path to a json file with parameters for the script.\nNOTE: if this is set, it is assumed the script exports a run(json_str) function.", default=[None])
    args = parser.parse_args()
    session = None
    script = None
    target_device = None
    script_params = None
    global _outfile

    if args.device[0] is not None:
        target_device = args.device[0]
    if args.parameters[0] is not None:
        script_params = args.parameters[0]
        _logger.info('reading parameters json from %s ...' % (script_params))
        if script_params.startswith('{'):
            _logger.info('parameters passed as JSON string: %s' %
                         (script_params))
        else:
            par = os.path.abspath(script_params)
            _logger.info('parameters passed as file path: %s' %
                         (par))
            with open(par, 'r') as f:
                script_params = f.read()

    hook_utils.adb_init_device(target_device)
    try:
        if args.dump_out_path is not None:
            path = args.dump_out_path[0]
            _logger.info('logging to file=%s' % (path))
            try:
                os.unlink(path)
            except:
                pass
            _outfile = open(path, 'wb')

        # run/install frida-server
        frida_restart = args.frida_restart
        if args.frida_server_path is not None:
            hook_utils.frida_server_install(
                args.frida_server_path[0], args.frida_force_reinstall)
            frida_restart = False
        hook_utils.frida_server_run(frida_restart)

        # run/restart process
        if args.kill:
            hook_utils.process_kill(args.package_name[0])
        hook_utils.app_run(args.package_name[0])

        # get session
        session = hook_utils.frida_get_session(
            args.package_name[0], target_device)

        # run script
        script = hook_utils.frida_load_script(
            session, args.js_path[0], handlers=[("message", on_message)], params=script_params)

        # done
        _logger.info('\nwaiting for CTRL-C or "detach" from script ...\n')
        while 1:
            global _detach_requested
            if _detach_requested:
                break

            sleep(1)

    except Exception as ex:
        _logger.exception(ex, stack_info=True)
    finally:
        # detach
        hook_utils.frida_cleanup(session, script)
        if _outfile is not None:
            _outfile.close()


if __name__ == "__main__":
    sys.exit(main())
