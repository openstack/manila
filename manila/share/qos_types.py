# Copyright 2026 SAP SE.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from oslo_config import cfg
from oslo_log import log

from manila import context
from manila import db

CONF = cfg.CONF
LOG = log.getLogger(__name__)


def get_qos_type_specs(qos_type_id, key=None):
    qos_type = db.qos_type_get(context.get_admin_context(),
                               qos_type_id)
    specs = qos_type['specs']
    if key:
        if specs.get(key):
            return specs.get(key)
        else:
            return None
    else:
        return specs


def get_specs_from_share(share):
    qos_type_id = share.get('qos_type_id', None)
    if not qos_type_id:
        return {}
    return get_qos_type_specs(qos_type_id)


def get_qos_type_name_from_share(share):
    qos_type_id = share.get('qos_type_id', None)
    if not qos_type_id:
        return ""
    qos_type = db.qos_type_get(context.get_admin_context(),
                               qos_type_id)
    return qos_type['name']
