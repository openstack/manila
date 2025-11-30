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


class FileSharesettingHandler(object):
    def __init__(self, rest_client, **kwargs):
        self.rest_client = rest_client
        self.validator = FileSharesettingValidator()
        self.convert = FileSharesettingModelConvert()

    def get_filesharesettings(self):
        _, be_filesharesettings = self.rest_client.get('/filesharesettings')

        self.validator.validate_get_filesharesettings_be_resp(
            be_filesharesettings)

        fe_filesharesettings = self.convert.\
            convert_filesharesettings_to_fe_model(
                be_filesharesettings)

        return fe_filesharesettings

    def _get_filesharesetting_by_name(self, be_filesharesetting_name):
        fe_filesharesettings = self.get_filesharesettings()
        for filesharesetting in fe_filesharesettings:
            if (filesharesetting['be_filesharesetting_name']
                    == be_filesharesetting_name):
                return filesharesetting

        msg = _("Not able to find filesharesetting by name. "
                "Filesharesetting name: %(filesharesetting_name)s") % {
                    'filesharesetting_name': be_filesharesetting_name}
        LOG.error(msg)
        raise exception.HPEAlletraB10000DriverException(reason=msg)


class FileSharesettingModelConvert(object):
    # GET /filesharesettings
    def convert_filesharesettings_to_fe_model(self, be_filesharesettings):
        fe_filesharesettings_resp = []
        filesharesetting_dict = be_filesharesettings['members']
        for key in filesharesetting_dict:
            fe_filesharesetting = self.\
                convert_filesharesetting_by_id_to_fe_model(
                    filesharesetting_dict[key])
            fe_filesharesettings_resp.append(fe_filesharesetting)
        return fe_filesharesettings_resp

    # GET /filesharesettings/{uid}
    def convert_filesharesetting_by_id_to_fe_model(self, be_filesharesetting):
        fe_filesharesetting = {}
        fe_filesharesetting['be_uid'] = be_filesharesetting['uid']
        fe_filesharesetting['be_filesharesetting_name'] = (
            be_filesharesetting['name'])

        be_clientinfo_val = None
        # If clientInfo list is empty, field is skipped in WSAPI GET resp
        if 'clientInfo' in be_filesharesetting:
            be_clientinfo_val = be_filesharesetting['clientInfo']
        fe_filesharesetting['be_filesharesetting_clientinfo'] = (
            be_clientinfo_val)
        return fe_filesharesetting


class FileSharesettingValidator(object):
    # GET /filesharesettings
    def validate_get_filesharesettings_be_resp(self, be_filesharesettings):
        if be_filesharesettings is None:
            msg = _("Received empty object from BE "
                    "Filesharesettings Response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'members' not in be_filesharesettings:
            msg = _("BE Filesharesettings Response does "
                    "not contain members field")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        filesharesettings_dict = be_filesharesettings['members']
        for key in filesharesettings_dict:
            try:
                self.validate_get_filesharesettings_by_id_be_resp(
                    filesharesettings_dict[key])
            except Exception as e:
                msg = _("Failed to validate filesharesetting data from "
                        "get filesharesettings call: "
                        "%(error)s") % {'error': str(e)}
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

    # GET /filesharesettings/{uid}
    def validate_get_filesharesettings_by_id_be_resp(
            self, be_filesharesetting):
        if be_filesharesetting is None:
            msg = _("Received empty object in filesharesetting by id")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'uid' not in be_filesharesetting:
            msg = _("Uid not found in get filesharesetting by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'name' not in be_filesharesetting:
            msg = _("Name not found in get filesharesetting by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        # Note: 'clientInfo' field is optional in backend
        # response. If clientInfo list is empty, the field
        # is skipped in WSAPI GET response.This is handled in
        # convert_filesharesetting_by_id_to_fe_model().
