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

from oslo_utils import excutils
from oslo_utils import strutils

from manila import exception
from manila.i18n import _
from manila.share.drivers.huawei import constants


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


class SmartQos(object):
    def __init__(self, helper):
        self.helper = helper

    def create_qos(self, qos, fs_id):
        policy_id = None
        try:
            # Check QoS priority.
            if self._check_qos_high_priority(qos):
                self.helper.change_fs_priority_high(fs_id)
            # Create QoS policy and activate it.
            (qos_id, fs_list) = self.helper.find_available_qos(qos)
            if qos_id is not None:
                self.helper.add_share_to_qos(qos_id, fs_id, fs_list)
            else:
                policy_id = self.helper.create_qos_policy(qos, fs_id)
                self.helper.activate_deactivate_qos(policy_id, True)
        except exception.InvalidInput:
            with excutils.save_and_reraise_exception():
                if policy_id is not None:
                    self.helper.delete_qos_policy(policy_id)

    def _check_qos_high_priority(self, qos):
        """Check QoS priority."""
        for key, value in qos.items():
            if (key.find('MIN') == 0) or (key.find('LATENCY') == 0):
                return True

        return False

    def delete_qos(self, qos_id):
        qos_info = self.helper.get_qos_info(qos_id)
        qos_status = qos_info['RUNNINGSTATUS']
        if qos_status != constants.STATUS_QOS_INACTIVATED:
            self.helper.activate_deactivate_qos(qos_id, False)
        self.helper.delete_qos_policy(qos_id)


class SmartX(object):
    def __init__(self, helper):
        self.helper = helper

    def get_smartx_extra_specs_opts(self, opts):
        opts = self.get_capabilities_opts(opts, 'dedupe')
        opts = self.get_capabilities_opts(opts, 'compression')
        opts = self.get_smartprovisioning_opts(opts)
        opts = self.get_smartcache_opts(opts)
        opts = self.get_smartpartition_opts(opts)
        opts = self.get_sectorsize_opts(opts)
        qos = self.get_qos_opts(opts)
        return opts, qos

    def get_capabilities_opts(self, opts, key):
        if strutils.bool_from_string(opts[key]):
            opts[key] = True
        else:
            opts[key] = False

        return opts

    def get_smartprovisioning_opts(self, opts):
        thin_provision = opts.get('thin_provisioning')
        if (thin_provision is None or
                strutils.bool_from_string(thin_provision)):
            opts['LUNType'] = constants.ALLOC_TYPE_THIN_FLAG
        else:
            opts['LUNType'] = constants.ALLOC_TYPE_THICK_FLAG

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

    def get_sectorsize_opts(self, opts):
        value = None
        if strutils.bool_from_string(opts.get('huawei_sectorsize')):
            value = opts.get('sectorsize')
        if not value:
            root = self.helper._read_xml()
            sectorsize = root.findtext('Filesystem/SectorSize')
            if sectorsize:
                sectorsize = sectorsize.strip()
                value = sectorsize

        if value:
            if value not in constants.VALID_SECTOR_SIZES:
                raise exception.InvalidInput(
                    reason=(_('Illegal value(%s) specified for sectorsize: '
                              'set to either 4, 8, 16, 32 or 64.') % value))
            else:
                opts['sectorsize'] = int(value)
        return opts

    def get_qos_opts(self, opts):
        qos = {}
        if not strutils.bool_from_string(opts.get('qos')):
            return

        for key, value in opts.items():
            if (key in constants.OPTS_QOS_VALUE) and value is not None:
                if (key.upper() != 'IOTYPE') and (int(value) <= 0):
                    err_msg = (_('QoS config is wrong. %(key)s'
                                 ' must be set greater than 0.')
                               % {'key': key})
                    raise exception.InvalidInput(reason=err_msg)
                elif ((key.upper() == 'IOTYPE')
                        and (value not in ['0', '1', '2'])):
                    raise exception.InvalidInput(
                        reason=(_('Illegal value specified for IOTYPE: '
                                  'set to either 0, 1, or 2.')))
                else:
                    qos[key.upper()] = value

        if len(qos) <= 1 or 'IOTYPE' not in qos:
            msg = (_('QoS config is incomplete. Please set more. '
                     'QoS policy: %(qos_policy)s.')
                   % {'qos_policy': qos})
            raise exception.InvalidInput(reason=msg)

        lowerlimit = constants.QOS_LOWER_LIMIT
        upperlimit = constants.QOS_UPPER_LIMIT
        if (set(lowerlimit).intersection(set(qos))
                and set(upperlimit).intersection(set(qos))):
            msg = (_('QoS policy conflict, both protection policy and '
                     'restriction policy are set. '
                     'QoS policy: %(qos_policy)s ')
                   % {'qos_policy': qos})
            raise exception.InvalidInput(reason=msg)

        return qos
