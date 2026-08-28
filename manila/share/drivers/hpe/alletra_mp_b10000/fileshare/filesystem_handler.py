# Copyright (c) 2025 Hewlett Packard Enterprise Development LP
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

from manila import exception
from manila.i18n import _
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import helpers

LOG = log.getLogger(__name__)


class FileSystemHandler(object):
    def __init__(self, rest_client, feature_support_handler, **kwargs):
        self.rest_client = rest_client
        self.feature_support_handler = feature_support_handler
        self.validator = FileSystemValidator(self.feature_support_handler)
        self.convert = FileSystemModelConvert(self.feature_support_handler)
        self.task = helpers.TaskHelper()

    def get_filesystems(self):
        _, be_filesystems = self.rest_client.get('/filesystems')

        self.validator.validate_get_filesystems_be_resp(be_filesystems)

        fe_filesystems = (
            self.convert.convert_filesystems_to_fe_model(
                be_filesystems))

        return fe_filesystems

    def snapshot_create(self, be_filesystem_uid, snapshot_name,
                        fe_snapshot_id):
        self.validator.validate_snapshot_create_fe_req(
            be_filesystem_uid, snapshot_name, fe_snapshot_id)
        be_snapshot_create = (
            self.convert.convert_snapshot_create_to_be_model(
                snapshot_name))

        self._post_filesystem_by_id(
            be_filesystem_uid,
            be_snapshot_create,
            "FILE_SYSTEM_SNAPSHOT_CREATE " + fe_snapshot_id)

    def snapshot_restore(self, be_filesystem_uid, be_snap_filesystem_name):
        self.validator.validate_snapshot_restore_fe_req(
            be_filesystem_uid, be_snap_filesystem_name)
        be_snapshot_restore = (
            self.convert.convert_snapshot_restore_to_be_model(
                be_snap_filesystem_name))

        self._post_filesystem_by_id(
            be_filesystem_uid,
            be_snapshot_restore,
            "FILE_SYSTEM_SNAPSHOT_RESTORE " +
            be_filesystem_uid + " from " + be_snap_filesystem_name)

    def snapshot_online(self, be_snap_filesystem_id):
        self.validator.validate_snapshot_online_fe_req(
            be_snap_filesystem_id)
        be_snapshot_online = (
            self.convert.convert_snapshot_online_to_be_model())

        self._post_filesystem_by_id(
            be_snap_filesystem_id,
            be_snapshot_online,
            "FILE_SYSTEM_SNAPSHOT_ONLINE " + be_snap_filesystem_id)

    def _get_filesystem_by_name(self, be_filesystem_name):
        fe_filesystems = self.get_filesystems()
        for filesystem in fe_filesystems:
            if (filesystem['be_filesystem_name'] == be_filesystem_name):
                return filesystem

        msg = _("Not able to find filesystem by name. Filesystem name: "
                "%(filesystem_name)s") % {
                    'filesystem_name': be_filesystem_name}
        LOG.error(msg)
        raise exception.HPEAlletraB10000DriverException(reason=msg)

    def _post_filesystem_by_id(self, be_filesystem_id, req_body, task_name):
        be_response_header, be_response_body = self.rest_client.post(
            '/filesystems/%s' % be_filesystem_id,
            body=req_body)
        self.validator.validate_filesystem_api_be_task_resp_header(
            be_response_header)

        be_task_id = self.task._extract_task_id_from_header(
            be_response_header)
        final_task_status = helpers.TaskWaiter(
            self.rest_client, be_task_id).wait_for_task()
        self.task._check_task_completion_status(
            final_task_status,
            task_name)


class FileSystemModelConvert(object):
    def __init__(self, feature_support_handler, **kwargs):
        self.feature_support_handler = feature_support_handler

    # GET /filesystems
    def convert_filesystems_to_fe_model(self, be_filesystems):
        fe_filesystems_resp = []
        filesystem_dict = be_filesystems['members']
        for key in filesystem_dict:
            fe_filesystem = self.convert_filesystem_by_id_to_fe_model(
                filesystem_dict[key])
            fe_filesystems_resp.append(fe_filesystem)
        return fe_filesystems_resp

    # GET /filesystems/{uid}
    def convert_filesystem_by_id_to_fe_model(self, be_filesystem):
        fe_filesystem = {}
        fe_filesystem['be_uid'] = be_filesystem['uid']
        fe_filesystem['be_filesystem_name'] = be_filesystem['name']
        fe_filesystem['be_filesystem_size'] = be_filesystem['vvSizeInMiB']
        fe_filesystem['be_filesystem_reduce'] = be_filesystem['reduce']

        if self.feature_support_handler.check_min_r6_device_version():
            if 'snapshotInfo' in be_filesystem:
                if 'copyOfName' in be_filesystem['snapshotInfo']:
                    fe_filesystem['be_parent_filesystem_name'] = (
                        be_filesystem['snapshotInfo']['copyOfName'])
        return fe_filesystem

    # Snapshot Create - POST /filesystems/{uid}
    def convert_snapshot_create_to_be_model(
            self, snapshot_name):

        snapshot_parameters = {
            "name": snapshot_name
        }
        be_snapshot_create = {
            "action": "FILE_SYSTEM_SNAPSHOT_CREATE",
            "parameters": snapshot_parameters}

        return be_snapshot_create

    # Snapshot Restore - POST /filesystems/{uid}
    def convert_snapshot_restore_to_be_model(self, be_snap_filesystem_name):

        snapshot_restore_parameters = {
            "source": be_snap_filesystem_name
        }
        be_snapshot_restore = {
            "action": "FILE_SYSTEM_SNAPSHOT_RESTORE",
            "parameters": snapshot_restore_parameters
        }

        return be_snapshot_restore

    # Snapshot Online - POST /filesystems/{uid}
    def convert_snapshot_online_to_be_model(self):

        be_snapshot_online = {
            "action": "FILE_SYSTEM_SNAPSHOT_ONLINE"}

        return be_snapshot_online


class FileSystemValidator(object):
    def __init__(self, feature_support_handler, **kwargs):
        self.feature_support_handler = feature_support_handler

    def validate_get_filesystems_be_resp(self, be_filesystems):
        if be_filesystems is None:
            msg = _("Received empty object from BE Filesystems Response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'members' not in be_filesystems:
            msg = _("BE Filesystems Response does not contain members field")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        filesystems_dict = be_filesystems['members']
        for key in filesystems_dict:
            try:
                self.validate_get_filesystem_by_id_be_resp(
                    filesystems_dict[key])
            except Exception as e:
                msg = _("Failed to validate filesystem data from get "
                        "filesystems call: %(error)s") % {'error': str(e)}
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

    def validate_get_filesystem_by_id_be_resp(self, be_filesystem):
        if be_filesystem is None:
            msg = _("Received empty object in filesystem by id")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'uid' not in be_filesystem:
            msg = _("Uid not found in get filesystem by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'name' not in be_filesystem:
            msg = _("Name not found in get filesystem by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'vvSizeInMiB' not in be_filesystem:
            msg = _("vvSizeInMiB not found in get filesystem by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'reduce' not in be_filesystem:
            msg = _("reduce not found in get filesystem by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if be_filesystem['reduce'] not in (True, False):
            msg = _(
                "reduce did not return a boolean value in get "
                "filesystem by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

    def validate_snapshot_create_fe_req(self, be_filesystem_uid,
                                        snapshot_name, fe_snapshot_id):
        if be_filesystem_uid is None:
            msg = _("Did not receive be_filesystem_uid parameter from "
                    "create_snapshot fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if snapshot_name is None:
            msg = _("Did not receive snapshot_name parameter from "
                    "create_snapshot fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if fe_snapshot_id is None:
            msg = _("Did not receive fe_snapshot_id parameter from "
                    "create_snapshot fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

    def validate_snapshot_restore_fe_req(self, be_filesystem_uid,
                                         be_snap_filesystem_name):
        if be_filesystem_uid is None:
            msg = _("Received empty object in be_filesystem_uid")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if be_snap_filesystem_name is None:
            msg = _("Received empty object in be_snap_filesystem_name")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

    def validate_snapshot_online_fe_req(self, be_snap_filesystem_id):
        if be_snap_filesystem_id is None:
            msg = _("Received empty value for BE Snapshot "
                    "Filesystem ID from FE")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

    # Tasks
    def validate_filesystem_api_be_task_resp_header(self, be_response_header):
        if 'Task_uri' not in be_response_header:
            msg = _("Filesystem be response header does not "
                    "have Task_uri field")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)
