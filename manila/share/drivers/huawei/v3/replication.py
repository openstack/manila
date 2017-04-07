# Copyright (c) 2016 Huawei Technologies Co., Ltd.
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

from oslo_log import log
from oslo_utils import strutils

from manila.common import constants as common_constants
from manila import exception
from manila.i18n import _
from manila.share.drivers.huawei import constants


LOG = log.getLogger(__name__)


class ReplicaPairManager(object):
    def __init__(self, helper):
        self.helper = helper

    def create(self, local_share_info, remote_device_wwn, remote_fs_id):
        local_share_name = local_share_info.get('name')

        try:
            local_fs_id = self.helper.get_fsid_by_name(local_share_name)
            if not local_fs_id:
                msg = _("Local fs was not found by name %s.")
                LOG.error(msg, local_share_name)
                raise exception.ReplicationException(
                    reason=msg % local_share_name)

            remote_device = self.helper.get_remote_device_by_wwn(
                remote_device_wwn)
            pair_params = {
                "LOCALRESID": local_fs_id,
                "LOCALRESTYPE": constants.FILE_SYSTEM_TYPE,
                "REMOTEDEVICEID": remote_device.get('ID'),
                "REMOTEDEVICENAME": remote_device.get('NAME'),
                "REMOTERESID": remote_fs_id,
                "REPLICATIONMODEL": constants.REPLICA_ASYNC_MODEL,
                "RECOVERYPOLICY": '2',
                "SYNCHRONIZETYPE": '1',
                "SPEED": constants.REPLICA_SPEED_MEDIUM,
            }

            pair_info = self.helper.create_replication_pair(pair_params)
        except Exception:
            msg = ("Failed to create replication pair for share %s.")
            LOG.exception(msg, local_share_name)
            raise

        self._sync_replication_pair(pair_info['ID'])

        return pair_info['ID']

    def _get_replication_pair_info(self, replica_pair_id):
        try:
            pair_info = self.helper.get_replication_pair_by_id(
                replica_pair_id)
        except Exception:
            LOG.exception('Failed to get replication pair info for '
                          '%s.', replica_pair_id)
            raise

        return pair_info

    def _check_replication_health(self, pair_info):
        if (pair_info['HEALTHSTATUS'] !=
                constants.REPLICA_HEALTH_STATUS_NORMAL):
            return common_constants.STATUS_ERROR

    def _check_replication_running_status(self, pair_info):
        if (pair_info['RUNNINGSTATUS'] in (
                constants.REPLICA_RUNNING_STATUS_SPLITTED,
                constants.REPLICA_RUNNING_STATUS_TO_RECOVER)):
            return common_constants.REPLICA_STATE_OUT_OF_SYNC

        if (pair_info['RUNNINGSTATUS'] in (
                constants.REPLICA_RUNNING_STATUS_INTERRUPTED,
                constants.REPLICA_RUNNING_STATUS_INVALID)):
            return common_constants.STATUS_ERROR

    def _check_replication_secondary_data_status(self, pair_info):
        if (pair_info['SECRESDATASTATUS'] in
                constants.REPLICA_DATA_STATUS_IN_SYNC):
            return common_constants.REPLICA_STATE_IN_SYNC
        else:
            return common_constants.REPLICA_STATE_OUT_OF_SYNC

    def _check_replica_state(self, pair_info):
        result = self._check_replication_health(pair_info)
        if result is not None:
            return result

        result = self._check_replication_running_status(pair_info)
        if result is not None:
            return result

        return self._check_replication_secondary_data_status(pair_info)

    def get_replica_state(self, replica_pair_id):
        try:
            pair_info = self._get_replication_pair_info(replica_pair_id)
        except Exception:
            # if cannot communicate to backend, return error
            LOG.error('Cannot get replica state, return %s',
                      common_constants.STATUS_ERROR)
            return common_constants.STATUS_ERROR

        return self._check_replica_state(pair_info)

    def _sync_replication_pair(self, pair_id):
        try:
            self.helper.sync_replication_pair(pair_id)
        except Exception as err:
            LOG.warning('Failed to sync replication pair %(id)s. '
                        'Reason: %(err)s',
                        {'id': pair_id, 'err': err})

    def update_replication_pair_state(self, replica_pair_id):
        pair_info = self._get_replication_pair_info(replica_pair_id)

        health = self._check_replication_health(pair_info)
        if health is not None:
            LOG.warning("Cannot update the replication %s "
                        "because it's not in normal status.",
                        replica_pair_id)
            return

        if strutils.bool_from_string(pair_info['ISPRIMARY']):
            # current replica is primary, not consistent with manila.
            # the reason for this circumstance is the last switch over
            # didn't succeed completely. continue the switch over progress..
            try:
                self.helper.switch_replication_pair(replica_pair_id)
            except Exception:
                msg = ('Replication pair %s primary/secondary '
                       'relationship is not right, try to switch over '
                       'again but still failed.')
                LOG.exception(msg, replica_pair_id)
                return

            # refresh the replication pair info
            pair_info = self._get_replication_pair_info(replica_pair_id)

        if pair_info['SECRESACCESS'] == constants.REPLICA_SECONDARY_RW:
            try:
                self.helper.set_pair_secondary_write_lock(replica_pair_id)
            except Exception:
                msg = ('Replication pair %s secondary access is R/W, '
                       'try to set write lock but still failed.')
                LOG.exception(msg, replica_pair_id)
                return

        if pair_info['RUNNINGSTATUS'] in (
                constants.REPLICA_RUNNING_STATUS_NORMAL,
                constants.REPLICA_RUNNING_STATUS_SPLITTED,
                constants.REPLICA_RUNNING_STATUS_TO_RECOVER):
            self._sync_replication_pair(replica_pair_id)

    def switch_over(self, replica_pair_id):
        pair_info = self._get_replication_pair_info(replica_pair_id)

        if strutils.bool_from_string(pair_info['ISPRIMARY']):
            LOG.warning('The replica to promote is already primary, '
                        'no need to switch over.')
            return

        replica_state = self._check_replica_state(pair_info)
        if replica_state != common_constants.REPLICA_STATE_IN_SYNC:
            # replica is not in SYNC state, can't be promoted
            msg = _('Data of replica %s is not synchronized, '
                    'can not promote.')
            raise exception.ReplicationException(
                reason=msg % replica_pair_id)

        try:
            self.helper.split_replication_pair(replica_pair_id)
        except Exception:
            # split failed
            # means replication pair is in an abnormal status,
            # ignore this exception, continue to cancel secondary write lock,
            # let secondary share accessible for disaster recovery.
            LOG.exception('Failed to split replication pair %s while '
                          'switching over.', replica_pair_id)

        try:
            self.helper.cancel_pair_secondary_write_lock(replica_pair_id)
        except Exception:
            LOG.exception('Failed to cancel replication pair %s '
                          'secondary write lock.', replica_pair_id)
            raise

        try:
            self.helper.switch_replication_pair(replica_pair_id)
            self.helper.set_pair_secondary_write_lock(replica_pair_id)
            self.helper.sync_replication_pair(replica_pair_id)
        except Exception:
            LOG.exception('Failed to completely switch over '
                          'replication pair %s.', replica_pair_id)

            # for all the rest steps,
            # because secondary share is accessible now,
            # the upper business may access the secondary share,
            # return success to tell replica is primary.
            return

    def delete_replication_pair(self, replica_pair_id):
        try:
            self.helper.split_replication_pair(replica_pair_id)
        except Exception:
            # Ignore this exception because replication pair may at some
            # abnormal status that supports deleting.
            LOG.warning('Failed to split replication pair %s '
                        'before deleting it. Ignore this exception, '
                        'and try to delete anyway.',
                        replica_pair_id)

        try:
            self.helper.delete_replication_pair(replica_pair_id)
        except Exception:
            LOG.exception('Failed to delete replication pair %s.',
                          replica_pair_id)
            raise

    def create_replica_pair(self, ctx,
                            local_share_info,
                            remote_device_wwn,
                            remote_fs_id):
        """Create replication pair for RPC call.

        This is for remote call, because replica pair can only be created
        by master node.
        """
        return self.create(local_share_info,
                           remote_device_wwn,
                           remote_fs_id)
