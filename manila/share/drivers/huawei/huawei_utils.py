# Copyright (c) 2015 Huawei Technologies Co., Ltd.
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

import copy

from oslo_log import log

from manila.i18n import _LE
from manila.share.drivers.huawei import constants
from manila.share import share_types


LOG = log.getLogger(__name__)


def get_share_extra_specs_params(type_id):
    """Return the parameters for creating the share."""
    opts = None
    if type_id is not None:
        specs = share_types.get_share_type_extra_specs(type_id)

        opts = _get_opts_from_specs(specs)
        LOG.debug('Get share type extra specs: %s', opts)

    return opts


def _get_opts_from_specs(specs):
    opts = copy.deepcopy(constants.OPTS_CAPABILITIES)
    opts.update(constants.OPTS_VALUE)

    for key, value in specs.items():

        # Get the scope, if using scope format
        scope = None
        key_split = key.split(':')
        if len(key_split) not in (1, 2):
            continue

        if len(key_split) == 1:
            key = key_split[0]
        else:
            scope = key_split[0]
            key = key_split[1]

        if scope:
            scope = scope.lower()
        if key:
            key = key.lower()

        # We want both the scheduler and the driver to act on the value.
        if ((not scope or scope == 'capabilities') and
                key in constants.OPTS_CAPABILITIES):
            words = value.split()

            if not (words and len(words) == 2 and words[0] == '<is>'):
                LOG.error(_LE("Extra specs must be specified as "
                              "capabilities:%s='<is> True'."), key)
            else:
                opts[key] = words[1].lower()

        if ((scope in constants.OPTS_CAPABILITIES) and
                (key in constants.OPTS_VALUE)):
            if ((scope in constants.OPTS_ASSOCIATE) and
                    (key in constants.OPTS_ASSOCIATE[scope])):
                opts[key] = value
    return opts
