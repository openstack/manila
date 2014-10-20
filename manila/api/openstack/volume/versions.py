# Copyright (c) 2013 OpenStack, LLC.
#
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

from manila.api import versions
from manila.i18n import _
from manila.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class Versions(versions.Versions):
    def __init__(self):
        LOG.warn(_('manila.api.openstack.volume.versions.Versions is '
                   'deprecated. Please use manila.api.versions.Versions '
                   'instead.'))
        super(Versions, self).__init__()
