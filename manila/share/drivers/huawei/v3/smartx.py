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

from oslo_utils import strutils

from manila import exception
from manila.i18n import _


class SmartPartition(object):
    def __init__(self, helper):
        self.helper = helper

    def add(self, opts, fsid):
        if not strutils.bool_from_string(opts['huawei_smartpartition']):
            return
        if not opts['partitionname']:
            raise exception.InvalidInput(
                reason=_('Partition name is None, please set '
                         'huawei_smartpartition:partitionname in key.'))

        partition_id = self.helper._get_partition_id_by_name(
            opts['partitionname'])
        if not partition_id:
            raise exception.InvalidInput(
                reason=_('Can not find partition id.'))

        self.helper._add_fs_to_partition(fsid, partition_id)


class SmartCache(object):
    def __init__(self, helper):
        self.helper = helper

    def add(self, opts, fsid):
        if not strutils.bool_from_string(opts['huawei_smartcache']):
            return
        if not opts['cachename']:
            raise exception.InvalidInput(
                reason=_('Illegal value specified for cache.'))

        cache_id = self.helper._get_cache_id_by_name(opts['cachename'])
        if not cache_id:
            raise exception.InvalidInput(
                reason=(_('Can not find cache id by cache name %(name)s.')
                        % {'name': opts['cachename']}))

        self.helper._add_fs_to_cache(fsid, cache_id)


class SmartX(object):
    def get_smartx_extra_specs_opts(self, opts):
        opts = self.get_capabilities_opts(opts, 'dedupe')
        opts = self.get_capabilities_opts(opts, 'compression')
        opts = self.get_smartprovisioning_opts(opts)
        opts = self.get_smartcache_opts(opts)
        opts = self.get_smartpartition_opts(opts)
        return opts

    def get_capabilities_opts(self, opts, key):
        if strutils.bool_from_string(opts[key]):
            opts[key] = True
        else:
            opts[key] = False

        return opts

    def get_smartprovisioning_opts(self, opts):
        if strutils.bool_from_string(opts['thin_provisioning']):
            opts['LUNType'] = 1
        else:
            opts['LUNType'] = 0

        return opts

    def get_smartcache_opts(self, opts):
        if strutils.bool_from_string(opts['huawei_smartcache']):
            if not opts['cachename']:
                raise exception.InvalidInput(
                    reason=_('Cache name is None, please set '
                             'huawei_smartcache:cachename in key.'))
        else:
            opts['cachename'] = None

        return opts

    def get_smartpartition_opts(self, opts):
        if strutils.bool_from_string(opts['huawei_smartpartition']):
            if not opts['partitionname']:
                raise exception.InvalidInput(
                    reason=_('Partition name is None, please set '
                             'huawei_smartpartition:partitionname in key.'))
        else:
            opts['partitionname'] = None

        return opts
