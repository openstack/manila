#!/usr/bin/env python

# Copyright 2013 NetApp
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Starter script for manila Share."""

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
    log.setup(CONF, "manila")
    utils.monkey_patch()
    launcher = service.process_launcher()
    if CONF.enabled_share_backends:
        for backend in CONF.enabled_share_backends:
            host = "%s@%s" % (CONF.host, backend)
            server = service.Service.create(host=host,
                                            service_name=backend,
                                            binary='manila-share')
            launcher.launch_service(server)
    else:
        server = service.Service.create(binary='manila-share')
        launcher.launch_service(server)
    launcher.wait()


if __name__ == '__main__':
    main()
