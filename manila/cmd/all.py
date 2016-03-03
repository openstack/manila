#!/usr/bin/env python

# Copyright 2011 OpenStack, LLC
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

"""Starter script for All manila services.

This script attempts to start all the manila services in one process.  Each
service is started in its own greenthread.  Please note that exceptions and
sys.exit() on the starting of a service are logged and the script will
continue attempting to launch the rest of the services.

"""

import eventlet
eventlet.monkey_patch()

import sys

from oslo_config import cfg
from oslo_log import log

from manila import i18n
i18n.enable_lazy()

from manila.common import config  # Need to register global_opts
from manila.i18n import _LE
from manila import service
from manila import utils
from manila import version

CONF = cfg.CONF


def main():
    log.register_options(CONF)
    config.set_middleware_defaults()
    CONF(sys.argv[1:], project='manila',
         version=version.version_string())
    log.setup(CONF, "manila")
    LOG = log.getLogger('manila.all')

    utils.monkey_patch()
    launcher = service.process_launcher()
    # manila-api
    try:
        server = service.WSGIService('osapi_share')
        launcher.launch_service(server, workers=server.workers or 1)
    except (Exception, SystemExit):
        LOG.exception(_LE('Failed to load osapi_share'))

    for binary in ['manila-share', 'manila-scheduler', 'manila-api',
                   'manila-data']:
        try:
            launcher.launch_service(service.Service.create(binary=binary))
        except (Exception, SystemExit):
            LOG.exception(_LE('Failed to load %s'), binary)
    launcher.wait()


if __name__ == '__main__':
    main()
