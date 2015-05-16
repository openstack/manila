# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

from oslo_config import cfg
from oslo_log import log
import paste.urlmap

from manila.i18n import _LW


LOG = log.getLogger(__name__)
CONF = cfg.CONF


def root_app_factory(loader, global_conf, **local_conf):
    if CONF.enable_v1_api:
        LOG.warning(_LW('The config option enable_v1_api is deprecated, is '
                        'not used, and will be removed in a future release.'))
    if CONF.enable_v2_api:
        LOG.warning(_LW('The config option enable_v2_api is deprecated, is '
                        'not used, and will be removed in a future release.'))
    return paste.urlmap.urlmap_factory(loader, global_conf, **local_conf)
