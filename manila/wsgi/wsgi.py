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

"""Manila OS API WSGI application."""


import sys

from oslo_config import cfg
from oslo_log import log
from oslo_reports import guru_meditation_report as gmr
from oslo_reports import opts as gmr_opts
from oslo_service import wsgi

# Need to register global_opts
from manila.common import config
from manila import rpc
from manila import service
from manila import version

CONF = cfg.CONF


def initialize_application():
    log.register_options(CONF)
    gmr_opts.set_defaults(CONF)
    CONF(sys.argv[1:], project="manila", version=version.version_string())
    config.verify_share_protocols()
    log.setup(CONF, "manila")

    gmr.TextGuruMeditation.setup_autorun(version, conf=CONF)
    rpc.init(CONF)
    service.setup_profiler("manila-api", CONF.host)
    return wsgi.Loader(CONF).load_app(name='osapi_share')
