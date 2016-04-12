#!/usr/bin/env python

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

"""Starter script for manila OS API."""

import eventlet
eventlet.monkey_patch()

import sys

from oslo_config import cfg
from oslo_log import log

from manila import i18n
i18n.enable_lazy()

from manila.common import config  # Need to register global_opts  # noqa
from manila import service
from manila import utils
from manila import version

CONF = cfg.CONF


def main():
    log.register_options(CONF)
    CONF(sys.argv[1:], project='manila',
         version=version.version_string())
    config.verify_share_protocols()
    log.setup(CONF, "manila")
    utils.monkey_patch()

    launcher = service.process_launcher()
    server = service.WSGIService('osapi_share')
    launcher.launch_service(server, workers=server.workers or 1)
    launcher.wait()


if __name__ == '__main__':
    main()
