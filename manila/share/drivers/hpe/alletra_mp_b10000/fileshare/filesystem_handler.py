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

LOG = log.getLogger(__name__)


class FileSystemHandler(object):
    def __init__(self, rest_client, **kwargs):
        self.rest_client = rest_client
        self.validator = FileSystemValidator()
        self.convert = FileSystemModelConvert()

    def get_filesystems(self):
        _, be_filesystems = self.rest_client.get('/filesystems')

        self.validator.validate_get_filesystems_be_resp(be_filesystems)

        fe_filesystems = self.convert.convert_filesystems_to_fe_model(
            be_filesystems)

        return fe_filesystems

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


class FileSystemModelConvert(object):
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
        return fe_filesystem


class FileSystemValidator(object):
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
