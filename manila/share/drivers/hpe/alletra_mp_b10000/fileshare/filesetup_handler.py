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


class FileSetupHandler(object):
    def __init__(self, rest_client, **kwargs):
        self.rest_client = rest_client
        self.validator = FileSetupValidator()
        self.convert = FileSetupModelConvert()

    def get_fileservice(self):
        _, be_fileservice = self.rest_client.get('/fileservice')

        self.validator.validate_get_fileservice_be_resp(be_fileservice)

        fe_fileservice = self.convert.convert_fileservice_to_fe_model(
            be_fileservice)

        return fe_fileservice

    def get_systems(self):
        _, be_systems = self.rest_client.get('/systems')

        self.validator.validate_get_systems_be_resp(be_systems)

        fe_systems = self.convert.convert_systems_to_fe_model(be_systems)

        return fe_systems

    def get_osinfo(self):
        _, be_osinfo = self.rest_client.get('/osinfo')

        self.validator.validate_get_osinfo_be_resp(be_osinfo)

        fe_osinfo = self.convert.convert_osinfo_to_fe_model(be_osinfo)

        return fe_osinfo


class FileSetupModelConvert(object):
    def convert_fileservice_to_fe_model(self, be_fileservice):
        fe_fileservice = {}
        if be_fileservice and 'members' in be_fileservice:
            fileservice_dict = be_fileservice['members']
            for key in fileservice_dict:
                # Include FE model fields
                fe_fileservice['be_is_fileservice_enabled'] = (
                    fileservice_dict[key]['isFileServiceEnabled'])
                fe_fileservice['be_available_capacity'] = (
                    fileservice_dict[key]['capacitySummary']
                    ['availableCapacity'])
                fe_fileservice['be_used_capacity'] = (
                    fileservice_dict[key]['capacitySummary']
                    ['usedCapacity'])
                fe_fileservice['be_total_capacity'] = (
                    fileservice_dict[key]['capacitySummary']
                    ['totalCapacity'])
            return fe_fileservice

        msg = _(
            "Failure in converting be fileservice to fe model. "
            "BE model %(be_model)s") % {
            'be_model': repr(be_fileservice)}
        LOG.error(msg)
        raise exception.HPEAlletraB10000DriverException(reason=msg)

    def convert_systems_to_fe_model(self, be_systems):
        fe_systems = {}
        if be_systems and 'members' in be_systems:
            systems_dict = be_systems['members']
            for key in systems_dict:
                fe_systems['version'] = (
                    systems_dict[key]['version']['base'])
            return fe_systems

        msg = _(
            "Failure in converting be systems to fe model. "
            "BE model %(be_model)s") % {
            'be_model': repr(be_systems)}
        LOG.error(msg)
        raise exception.HPEAlletraB10000DriverException(reason=msg)

    def convert_osinfo_to_fe_model(self, be_osinfo):
        fe_osinfo = {}
        if be_osinfo and 'members' in be_osinfo:
            osinfo_dict = be_osinfo['members']
            for key in osinfo_dict:
                fe_osinfo['be_is_fileservice_supported'] = (
                    osinfo_dict[key]['OsFVars']['isFileServiceSupported'])
            return fe_osinfo

        msg = _(
            "Failure in converting be osinfo to fe model. "
            "BE model %(be_model)s") % {
            'be_model': repr(be_osinfo)}
        LOG.error(msg)
        raise exception.HPEAlletraB10000DriverException(reason=msg)


class FileSetupValidator(object):
    def validate_get_fileservice_be_resp(self, be_fileservice):
        if be_fileservice is None:
            msg = _("Received empty object from BE Fileservice Response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'members' not in be_fileservice:
            msg = _("BE Fileservice Response does not contain members field")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        fileservice_dict = be_fileservice['members']
        if len(fileservice_dict) == 0:
            msg = _("BE Fileservice members field has no keys")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)
        elif len(fileservice_dict) > 1:
            # Allowing to continue in case of multiple keys. We will only pick
            # up first key
            msg = _("BE Fileservice members field has more than 1 key")
            LOG.error(msg)

        for key in fileservice_dict:
            if 'isFileServiceEnabled' not in fileservice_dict[key]:
                msg = _(
                    "BE Fileservice Response members does not have "
                    "isFileServiceEnabled field")
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

            if 'capacitySummary' not in fileservice_dict[key]:
                msg = _(
                    "BE Fileservice Response members does not have "
                    "capacitySummary field")
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

            capacity_summary = fileservice_dict[key]['capacitySummary']
            if 'availableCapacity' not in capacity_summary:
                msg = _(
                    "BE Fileservice Response members capacitySummary "
                    "does not have availableCapacity field")
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

            if 'totalCapacity' not in capacity_summary:
                msg = _(
                    "BE Fileservice Response members capacitySummary "
                    "does not have totalCapacity field")
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

            if 'usedCapacity' not in fileservice_dict[key]['capacitySummary']:
                msg = _(
                    "BE Fileservice Response members capacitySummary "
                    "does not have usedCapacity field")
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

    def validate_get_systems_be_resp(self, be_systems):
        if be_systems is None:
            msg = _(
                "Received empty object from BE Systems Response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'members' not in be_systems:
            msg = _("BE Systems Response does not contain members field")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        systems_dict = be_systems['members']
        if len(systems_dict) == 0:
            msg = _("BE Systems members field has no keys")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)
        elif len(systems_dict) > 1:
            # Allowing to continue in case of multiple keys. We will only pick
            # up first key
            msg = _("BE Systems members field has more than 1 key")
            LOG.error(msg)

        for key in systems_dict:
            if 'version' not in systems_dict[key]:
                msg = _(
                    "BE Systems Response members does not have "
                    "version field")
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

            if 'base' not in systems_dict[key]['version']:
                msg = _("BE Systems version field does not have base field")
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

    def validate_get_osinfo_be_resp(self, be_osinfo):
        if be_osinfo is None:
            msg = _("Received empty object from BE OS-Info Response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'members' not in be_osinfo:
            msg = _(
                "BE OS-Info Response does not contain members field")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        osinfo_dict = be_osinfo['members']
        if len(osinfo_dict) == 0:
            msg = _("BE OS-Info members field has no keys")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)
        elif len(osinfo_dict) > 1:
            # Allowing to continue in case of multiple keys. We will only pick
            # up first key
            msg = _("BE Os-Info members field has more than 1 key")
            LOG.error(msg)

        for key in osinfo_dict:
            if 'OsFVars' not in osinfo_dict[key]:
                msg = _("BE Os-Info field does not have OsFVars field")
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

            if 'isFileServiceSupported' not in osinfo_dict[key]['OsFVars']:
                msg = _(
                    "BE isFileServiceSupported field within Os-Info "
                    "field does not exist")
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)
