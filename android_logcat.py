#!/usr/bin/env python3
import argparse
import logging
import sys
from time import sleep

import coloredlogs
import hook_utils.hook_utils as hook_utils

coloredlogs.install(level='INFO')
_logger = logging.getLogger()


def main():
    parser = argparse.ArgumentParser(
        description='run adb logcat, optionally filtering for packagename.')
    parser.add_argument('--package_name', nargs=1,
                        help='optional packagename for filtering output.', default=[None])
    parser.add_argument('--device', nargs=1,
                        help="if set, use plugged device with the given serial.", default=[None])
    args = parser.parse_args()
    target_device=None
    package_name=None
    if args.device[0] is not None:
        target_device = args.device[0]
    if args.package_name[0] is not None:
        package_name=args.package_name[0]
    
    hook_utils.adb_init_device(target_device)
    try:
        hook_utils.adb_logcat(package_name, target_device)

    except Exception as ex:
        _logger.exception(ex, stack_info=True)
        

if __name__ == "__main__":
    sys.exit(main())
