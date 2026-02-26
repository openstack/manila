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
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    constants)
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    filesharesetting_handler)
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    filesystem_handler)
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import helpers
from manila import utils

LOG = log.getLogger(__name__)


class FileShareHandler(object):
    def __init__(self, rest_client, **kwargs):
        self.rest_client = rest_client
        self.validator = FileShareValidator()
        self.convert = FileShareModelConvert()
        self.task = helpers.TaskHelper()

        self.filesystem_handler = filesystem_handler.FileSystemHandler(
            rest_client)
        self.filesharesetting_handler = (
            filesharesetting_handler.FileSharesettingHandler(
                rest_client)
        )

    # BE APIs
    def create_fileshare(self, fe_create_fileshare, extra_specs):
        self.validator.validate_create_fileshare_fe_req(
            fe_create_fileshare, extra_specs)
        be_create_fileshare = self.convert.convert_fileshare_to_be_model(
            fe_create_fileshare, extra_specs)

        be_response_header, be_response_body = self.rest_client.post(
            '/fileshares', body=be_create_fileshare)
        self.validator.validate_fileshare_api_be_task_resp_header(
            be_response_header)

        be_task_id = self.task._extract_task_id_from_header(
            be_response_header)
        final_task_status = helpers.TaskWaiter(
            self.rest_client, be_task_id).wait_for_task()

        self.task._check_task_completion_status(
            final_task_status,
            "CREATE_FILESHARE " +
            fe_create_fileshare['id'])

        be_fileshare_name, be_filesystem_name, be_sharesetting_name = (
            self.convert._get_be_share_resource_names(
                fe_create_fileshare)
        )
        msg = _(
            "Create fileshare backend operation completed for id: %(fe_id)s. "
            "Backend share name %(be_name)s") % {
            'fe_id': fe_create_fileshare['id'],
            'be_name': be_fileshare_name}
        LOG.info(msg)
        return be_fileshare_name, be_filesystem_name, be_sharesetting_name

    def get_fileshares(self):
        _, be_fileshares = self.rest_client.get('/fileshares')

        self.validator.validate_get_fileshares_be_resp(be_fileshares)

        fe_fileshares = self.convert.convert_fileshares_to_fe_model(
            be_fileshares)

        return fe_fileshares

    def get_fileshare_by_id(self, be_fileshare_uid):
        _, be_fileshare = self.rest_client.get(
            '/fileshares/%s' % be_fileshare_uid)

        self.validator.validate_get_fileshare_by_id_be_resp(be_fileshare)

        fe_fileshare = self.convert.convert_fileshare_by_id_to_fe_model(
            be_fileshare)

        return fe_fileshare

    def delete_fileshare_by_id(self, fe_fileshare_id, be_fileshare_uid):
        be_response_header, be_response_body = self.rest_client.delete(
            '/fileshares/%s' % be_fileshare_uid)
        self.validator.validate_fileshare_api_be_task_resp_header(
            be_response_header)

        be_task_id = self.task._extract_task_id_from_header(be_response_header)
        final_task_status = helpers.TaskWaiter(
            self.rest_client, be_task_id).wait_for_task()
        self.task._check_task_completion_status(
            final_task_status, "DELETE_FILESHARE " + be_fileshare_uid)

        msg = _(
            "Delete fileshare backend operation completed for id: %(fe_id)s. "
            "Backend share id: %(be_id)s") % {
            'fe_id': fe_fileshare_id,
            'be_id': be_fileshare_uid}
        LOG.info(msg)

    def edit_fileshare_by_id(
            self,
            fe_fileshare_id,
            be_fileshare_uid,
            be_filesystem_name,
            extra_specs,
            expand_filesystem,
            fe_existing_size,
            fe_new_size,
            update_access_rules,
            fe_new_access_rules):
        be_existing_filesystem_size = None
        if expand_filesystem:
            try:
                fe_filesystem = (
                    self.filesystem_handler._get_filesystem_by_name(
                        be_filesystem_name)
                )
            except Exception as e:
                msg = _("Edit fileshare failed for id"
                        " %(share_id)s. Error: %(error)s") % {
                    'share_id': fe_fileshare_id, 'error': str(e)}
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)
            be_existing_filesystem_size = fe_filesystem['be_filesystem_size']

        self.validator.validate_edit_fileshare_fe_req(
            be_fileshare_uid,
            extra_specs,
            expand_filesystem,
            fe_existing_size,
            fe_new_size,
            be_existing_filesystem_size,
            update_access_rules,
            fe_new_access_rules)

        LOG.debug(
            "Received access rules from Manila for share %s: %s",
            fe_fileshare_id,
            fe_new_access_rules)

        be_edit_fileshare = self.convert.convert_edit_fileshare_to_be_model(
            be_fileshare_uid,
            extra_specs,
            expand_filesystem,
            fe_existing_size,
            fe_new_size,
            update_access_rules,
            fe_new_access_rules)

        be_response_header, be_response_body = self.rest_client.post(
            '/fileshares', body=be_edit_fileshare)

        try:
            self.validator.validate_fileshare_api_be_task_resp_header(
                be_response_header)
            be_task_id = self.task._extract_task_id_from_header(
                be_response_header)
            final_task_status = helpers.TaskWaiter(
                self.rest_client, be_task_id).wait_for_task()
            self.task._check_task_completion_status(
                final_task_status, "EDIT_FILESHARE " + be_fileshare_uid)
        except exception.HPEAlletraB10000DriverException:
            # If the same access rule list is sent to backend again,
            # we will receive 200 OK with no Task_uri header
            if be_response_header.status == 200:
                msg = _(
                    "Edit fileshare backend operation completed synchronously "
                    "for id: %(fe_id)s. Backend share id: %(be_id)s. "
                    "Same access rule list was sent to backend.") % {
                    'fe_id': fe_fileshare_id,
                    'be_id': be_fileshare_uid}
                LOG.info(msg)
            else:
                raise

        msg = _(
            "Edit fileshare backend operation completed for id: %(fe_id)s. "
            "Backend share id: %(be_id)s") % {
            'fe_id': fe_fileshare_id,
            'be_id': be_fileshare_uid}
        LOG.info(msg)

    def manage_fileshare(self, fe_manage_fileshare, extra_specs):
        self.validator.validate_manage_fileshare_fe_req(
            fe_manage_fileshare, extra_specs)
        be_manage_fileshare = (
            self.convert.convert_manage_fileshare_to_be_model(
                fe_manage_fileshare, extra_specs)
        )

        try:
            fe_fileshare = self._get_fileshare_by_hostip_mountpath(
                be_manage_fileshare['be_host_ip'],
                be_manage_fileshare['be_mount_path'])
        except Exception as e:
            msg = (
                _(
                    "Manage fileshare failed for hostip %(be_host_ip)s "
                    "mountpath %(be_mount_path)s. Error: %(error)s") % {
                    'be_host_ip': be_manage_fileshare['be_host_ip'],
                    'be_mount_path': be_manage_fileshare['be_mount_path'],
                    'error': str(e)})
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        # Validate reduce & accessrules for the share
        try:
            fe_filesystem = self.filesystem_handler._get_filesystem_by_name(
                fe_fileshare['be_filesystem_name'])
        except Exception as e:
            msg = (
                _(
                    "Manage fileshare failed for hostip "
                    "%(be_host_ip)s mountpath %(be_mount_path)s. "
                    "Error: %(error)s") % {
                    'be_host_ip': be_manage_fileshare['be_host_ip'],
                    'be_mount_path': be_manage_fileshare['be_mount_path'],
                    'error': str(e)})
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)
        try:
            fe_filesharesetting = (
                self.filesharesetting_handler._get_filesharesetting_by_name(
                    fe_fileshare['be_sharesetting_name'])
            )
        except Exception as e:
            msg = (
                _(
                    "Manage fileshare failed for hostip "
                    "%(be_host_ip)s mountpath %(be_mount_path)s. "
                    "Error: %(error)s") % {
                    'be_host_ip': be_manage_fileshare['be_host_ip'],
                    'be_mount_path': be_manage_fileshare['be_mount_path'],
                    'error': str(e)})
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if (fe_filesystem['be_filesystem_reduce'] !=
                be_manage_fileshare['fe_reduce']):
            msg = (
                _(
                    "Manage fileshare failed for hostip "
                    "%(be_host_ip)s mountpath %(be_mount_path)s. "
                    "Reduce parameter value does not match between "
                    "share type and backend share."
                    "(DefaultSharetypeReduce:False) "
                    "Sharetype Reduce: %(share_type_reduce)s "
                    "BE Reduce: %(be_share_reduce)s") % {
                    'be_host_ip': be_manage_fileshare['be_host_ip'],
                    'be_mount_path': be_manage_fileshare['be_mount_path'],
                    'share_type_reduce': be_manage_fileshare['fe_reduce'],
                    'be_share_reduce': fe_filesystem['be_filesystem_reduce']})
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        clientinfo = fe_filesharesetting.get('be_filesharesetting_clientinfo')
        if clientinfo is not None and len(clientinfo) > 0:
            # Allow managing shares with empty or default clientinfo
            if not self.validator._is_default_clientinfo(clientinfo):
                be_host_ip = be_manage_fileshare['be_host_ip']
                be_mount_path = be_manage_fileshare['be_mount_path']
                msg = (_("Manage fileshare failed for hostip "
                         "%(be_host_ip)s "
                         "mountpath %(be_mount_path)s. "
                         "Backend sharesetting has values. "
                         "Managing a fileshare with existing "
                         "sharesettings(hostaccess) "
                         "rules set in the alletra backend is "
                         "not supported. Please clear "
                         "the existing sharesetting rules list "
                         "from the backend and try "
                         "again.") % {
                    'be_host_ip': be_host_ip,
                    'be_mount_path': be_mount_path})
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(
                    reason=msg)

        # Validate that BE filesystem size is a multiple of 1024 MiB (1 GiB)
        be_filesystem_size_mib = fe_filesystem['be_filesystem_size']
        if be_filesystem_size_mib % 1024 != 0:
            next_multiple = ((be_filesystem_size_mib // 1024) + 1) * 1024
            increase_by = next_multiple - be_filesystem_size_mib
            msg = (_("Manage fileshare failed for hostip %(be_host_ip)s "
                     "mountpath %(be_mount_path)s. "
                     "Backend filesystem size %(current_size)s MiB must be "
                     "a multiple of 1024 MiB (1 GiB). "
                     "Please increase the filesystem size by %(increase_by)s "
                     "MiB to %(next_multiple)s MiB (%(next_multiple_gb)s GiB)"
                     " and try again.") % {
                'be_host_ip': be_manage_fileshare['be_host_ip'],
                'be_mount_path': be_manage_fileshare['be_mount_path'],
                'current_size': be_filesystem_size_mib,
                'increase_by': increase_by,
                'next_multiple': next_multiple,
                'next_multiple_gb': next_multiple // 1024})
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        # Reset access rules to default rules
        try:
            empty_access_rules = []
            self.edit_fileshare_by_id(
                fe_manage_fileshare['id'],
                fe_fileshare['be_uid'],
                fe_fileshare['be_filesystem_name'],
                extra_specs,
                False,
                None,
                None,
                True,
                empty_access_rules)
        except Exception as e:
            LOG.warning(
                "Failed to reset access rules to default during manage for "
                "share %(share_id)s: %(error)s. Share will be managed "
                "successfully, but default block access rule has not been "
                "set.",
                {'share_id': fe_manage_fileshare['id'], 'error': str(e)})

        return fe_fileshare, fe_filesystem['be_filesystem_size']

    # Helpers
    def _get_fileshare_by_name(
            self,
            be_fileshare_name,
            be_filesystem_name,
            be_sharesetting_name):
        fe_fileshares = self.get_fileshares()
        for fileshare in fe_fileshares:
            if (fileshare['be_fileshare_name'] == be_fileshare_name and
                    fileshare['be_filesystem_name'] == be_filesystem_name and
                    fileshare['be_sharesetting_name'] == (
                        be_sharesetting_name)):
                # We assume only one share will exist with this condition
                # Due to BE uniqueness constraint on filesystem and
                # sharesetting name
                return fileshare

        msg = _(
            "Not able to find fileshare by name. "
            "Fileshare name: %(fs_name)s, "
            "Filesystem name: %(filesystem_name)s, "
            "Sharesetting name: %(sharesetting_name)s") % {
            'fs_name': be_fileshare_name,
            'filesystem_name': be_filesystem_name,
            'sharesetting_name': be_sharesetting_name}
        LOG.error(msg)
        raise exception.HPEAlletraB10000DriverException(reason=msg)

    def _get_fileshare_by_hostip_mountpath(self, be_host_ip, be_mount_path):
        fe_fileshares = self.get_fileshares()
        for fileshare in fe_fileshares:
            if (fileshare['host_ip'] == be_host_ip and
                    fileshare['mount_path'] == be_mount_path):
                return fileshare

        msg = _("Not able to find fileshare by hostip and mountpath."
                "Host IP: %(host_ip)s, Mount Path: %(mount_path)s") % {
                    'host_ip': be_host_ip,
                    'mount_path': be_mount_path
            }
        LOG.error(msg)
        raise exception.HPEAlletraB10000DriverException(reason=msg)

    def _compare_values_with_be_share(
            self,
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name):
        fe_fileshare = self.get_fileshare_by_id(be_share_id)

        self.validator._validate_be_share_values(
            fe_fileshare['be_uid'],
            fe_fileshare['be_fileshare_name'],
            fe_fileshare['be_filesystem_name'],
            fe_fileshare['be_sharesetting_name'],
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name)


class FileShareModelConvert(object):
    # Create fileshare
    def convert_fileshare_to_be_model(self, fe_create_fileshare, extra_specs):
        be_fileshare_name, be_filesystem_name, be_sharesetting_name = (
            self._get_be_share_resource_names(
                fe_create_fileshare
            )
        )

        be_filesystem_size_mib = int(fe_create_fileshare['size']) * 1024

        reduce_val = True
        reduce_str = extra_specs.get('hpe_alletra_b10000:reduce')
        if reduce_str is not None:
            # Value already validated in _validate_share_type_extra_specs
            if reduce_str.lower() == "true":
                reduce_val = True
            else:
                reduce_val = False
        else:
            # If reduce is not specified, check dedupe and compression
            dedupe_str = extra_specs.get('dedupe')
            compression_str = extra_specs.get('compression')
            if dedupe_str is not None and compression_str is not None:
                # Both dedupe and compression will have the same value
                if dedupe_str.lower() == "true":
                    reduce_val = True
                else:
                    reduce_val = False

        # Build be create_fileshare_request
        create_fileshare_operation_params = {
            "name": be_fileshare_name,
            "filesystem": be_filesystem_name,
            "filesharesetting": be_sharesetting_name}
        create_fileshare_operation = {
            "action": "CREATE_FILE_SHARE",
            "parameters": create_fileshare_operation_params}

        create_filesystem_operation_params = {
            "name": be_filesystem_name,
            "sizeInMiB": be_filesystem_size_mib,
            "reduce": reduce_val}
        create_filesystem_operation = {
            "action": "CREATE_FILE_SYSTEM",
            "parameters": create_filesystem_operation_params}

        create_sharesetting_operation_params = {
            "name": be_sharesetting_name,
            "clientInfo": constants.BE_DEFAULT_CLIENT_INFO_LIST}
        create_sharesetting_operation = {
            "action": "CREATE_FILE_SHARE_SETTINGS",
            "parameters": create_sharesetting_operation_params}

        be_create_fileshare = {
            "batch": "CREATE_COMPLEX_FILE_SHARE",
            "ordered": True,
            "operations": [
                create_fileshare_operation,
                create_filesystem_operation,
                create_sharesetting_operation]}

        return be_create_fileshare

    # Get fileshare
    def convert_fileshares_to_fe_model(self, be_fileshares):
        fe_fileshares_resp = []
        fileshare_dict = be_fileshares['members']
        for key in fileshare_dict:
            fe_fileshare = self.convert_fileshare_by_id_to_fe_model(
                fileshare_dict[key])
            fe_fileshares_resp.append(fe_fileshare)
        return fe_fileshares_resp

    # Get fileshare by uid
    def convert_fileshare_by_id_to_fe_model(self, be_fileshare):
        fe_fileshare = {}
        fe_fileshare['be_uid'] = be_fileshare['uid']
        fe_fileshare['be_fileshare_name'] = be_fileshare['name']
        fe_fileshare['be_filesystem_name'] = (
            be_fileshare['filesystem']['name']
        )
        fe_fileshare['be_sharesetting_name'] = (
            be_fileshare['sharesettings']['name']
        )
        fe_fileshare['host_ip'] = be_fileshare['hostip']
        fe_fileshare['mount_path'] = be_fileshare['mountpath']
        return fe_fileshare

    # Edit fileshare by uid
    def convert_edit_fileshare_to_be_model(
            self,
            be_fileshare_uid,
            extra_specs,
            expand_filesystem,
            fe_existing_size,
            fe_new_size,
            update_access_rules,
            fe_new_access_rules):

        # Build the edit_fileshare_request
        operations_list = []

        if expand_filesystem:
            fe_new_size_mib = fe_new_size * 1024
            fe_existing_size_mib = fe_existing_size * 1024
            be_additional_size_mib = fe_new_size_mib - fe_existing_size_mib

            edit_filesystem_operation_params = {
                "sizeInMiB": be_additional_size_mib}
            edit_filesystem_operation = {
                "action": "MODIFY_FILE_SYSTEM",
                "parameters": edit_filesystem_operation_params}
            operations_list.append(edit_filesystem_operation)

        if update_access_rules:
            squash_val = 'root_squash'
            squash_str = extra_specs.get('hpe_alletra_b10000:squash_option')
            if squash_str is not None:
                squash_val = squash_str.lower()

            be_client_info_list = []
            for access_rule in fe_new_access_rules:
                if access_rule['access_type'] == "ip":
                    be_client_info = {}
                    ip_address = access_rule['access_to']

                    # Convert 0.0.0.0/0 to * for backend
                    if ip_address in ('0.0.0.0/0', '0.0.0.0/00'):
                        be_client_info['ipaddress'] = '*'
                    else:
                        be_client_info['ipaddress'] = ip_address

                    be_client_info['access'] = access_rule['access_level']
                    be_client_info['options'] = squash_val
                    be_client_info_list.append(be_client_info)

            # If no access rules provided, use default secure rule
            if not be_client_info_list:
                be_client_info_list = constants.BE_DEFAULT_CLIENT_INFO_LIST

            modify_sharesettings_operation_params = {
                "clientInfo": be_client_info_list}
            modify_sharesettings_operation = {
                "action": "MODIFY_FILE_SHARE_SETTINGS",
                "parameters": modify_sharesettings_operation_params}
            operations_list.append(modify_sharesettings_operation)

        be_edit_fileshare = {
            "batch": "MODIFY_COMPLEX_FILE_SHARE",
            "ordered": True,
            "uuid": be_fileshare_uid,
            "operations": operations_list}

        return be_edit_fileshare

    # Manage Existing Fileshare
    def convert_manage_fileshare_to_be_model(self, fe_fileshare, extra_specs):
        be_manage_fileshare = {}
        export_path = fe_fileshare['export_locations'][0]['path']
        path_parts = export_path.split(':', 1)  # Split into at most 2 parts
        ip_address, mount_path = path_parts
        be_manage_fileshare['be_host_ip'] = ip_address
        be_manage_fileshare['be_mount_path'] = mount_path

        reduce_val = True
        reduce_str = extra_specs.get('hpe_alletra_b10000:reduce')
        if reduce_str is not None:
            if reduce_str.lower() == "true":
                reduce_val = True
            else:
                reduce_val = False
        else:
            # If reduce is not specified, check dedupe and compression
            dedupe_str = extra_specs.get('dedupe')
            compression_str = extra_specs.get('compression')
            if dedupe_str is not None and compression_str is not None:
                # Both dedupe and compression will have the same value
                if dedupe_str.lower() == "true":
                    reduce_val = True
                else:
                    reduce_val = False
        be_manage_fileshare['fe_reduce'] = reduce_val

        squash_option = extra_specs.get('hpe_alletra_b10000:squash_option')
        squash_val = 'root_squash'
        if squash_option is not None:
            squash_val = squash_option.lower()
        be_manage_fileshare['fe_squash_option'] = squash_val

        return be_manage_fileshare

    # Helper Methods
    def _get_be_share_resource_names(self, share):
        return (
            self._get_be_share_name(share),
            self._get_be_filesystem_name(share),
            self._get_be_sharesetting_name(share)
        )

    def _get_be_share_name(self, share):
        return share['name']

    def _get_be_filesystem_name(self, share):
        return constants.BE_FILESYSTEM_NAME % share['id']

    def _get_be_sharesetting_name(self, share):
        return constants.BE_SHARESETTING_NAME % share['id']


class FileShareValidator(object):
    # Create fileshare
    def validate_create_fileshare_fe_req(self, fe_fileshare, extra_specs):
        if 'size' not in fe_fileshare:
            msg = _("Did not receive size parameter "
                    "from create_fileshare fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if not isinstance(fe_fileshare['size'], int):
            msg = _("Size parameter must "
                    "be an integer, received type: "
                    "%s") % type(fe_fileshare['size']).__name__
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        # Validate filesystem size limits: minimum 1 GB, maximum 64 TB
        share_size_gb = fe_fileshare['size']
        min_size_gb = constants.BE_MIN_FILESYSTEM_SIZE_GiB
        max_size_gb = constants.BE_MAX_FILESYSTEM_SIZE_GiB

        if share_size_gb < min_size_gb:
            msg = _("Filesystem size must be at "
                    "least %(min_size)s GB. Requested: "
                    "%(requested)s GB") % {'min_size': min_size_gb,
                                           'requested': share_size_gb}
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if share_size_gb > max_size_gb:
            msg = _("Filesystem size must not exceed %(max_size)s "
                    "GB (64 TB). Requested: %(requested)s "
                    "GB") % {'max_size': max_size_gb,
                             'requested': share_size_gb}
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if 'id' not in fe_fileshare:
            msg = _("Did not receive id parameter from "
                    "create_fileshare fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if 'name' not in fe_fileshare:
            msg = _("Did not receive name parameter from "
                    "create_fileshare fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        self._validate_share_type_extra_specs(extra_specs)

    # Tasks
    def validate_fileshare_api_be_task_resp_header(self, be_response_header):
        if 'Task_uri' not in be_response_header:
            msg = _("Fileshare be response header does not "
                    "have Task_uri field")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

    # Get fileshares
    def validate_get_fileshares_be_resp(self, be_fileshares):
        if be_fileshares is None:
            msg = _("Received empty object from BE Fileshare Response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'members' not in be_fileshares:
            msg = _("BE Fileshare Response does not contain members field")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        fileshare_dict = be_fileshares['members']
        for key in fileshare_dict:
            try:
                self.validate_get_fileshare_by_id_be_resp(fileshare_dict[key])
            except Exception as e:
                msg = _("Failed to validate fileshare data from get "
                        "fileshares call: %(error)s") % {'error': str(e)}
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

    # Get fileshare by uid
    def validate_get_fileshare_by_id_be_resp(self, be_fileshare):
        if be_fileshare is None:
            msg = _("Received empty object in fileshare by id")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'uid' not in be_fileshare:
            msg = _("Uid not found in get fileshare by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'name' not in be_fileshare:
            msg = _("Name not found in get fileshare by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'filesystem' not in be_fileshare:
            msg = _("Filesystem object not found in get "
                    "fileshare by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'name' not in be_fileshare['filesystem']:
            msg = _(
                "Name within filesystem object not found in get "
                "fileshare by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'sharesettings' not in be_fileshare:
            msg = _("Sharesetting object not found in get "
                    "fileshare by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'name' not in be_fileshare['sharesettings']:
            msg = _(
                "Name within sharesetting object not found in get "
                "fileshare by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'hostip' not in be_fileshare:
            msg = _("Host IP not found in get fileshare by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if 'mountpath' not in be_fileshare:
            msg = _("Mount path not found in get fileshare by id response")
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

    def _validate_be_share_values(
            self,
            be_share_id,
            be_share_name,
            be_filesystem_name,
            be_sharesetting_name,
            stored_be_share_id,
            stored_be_share_name,
            stored_be_filesystem_name,
            stored_be_sharesetting_name):
        if be_share_id != stored_be_share_id:
            msg = _("Share ID does not match between stored "
                    "FE and Alletra BE Share. FE Stored: %(fe_val)s "
                    "BE: %(be_val)s") % {'fe_val': stored_be_share_id,
                                         'be_val': be_share_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if stored_be_share_name != be_share_name:
            msg = _("Share Name does not match between stored FE and Alletra "
                    "BE Share. FE Stored: %(fe_val)s "
                    "BE: %(be_val)s") % {'fe_val': stored_be_share_name,
                                         'be_val': be_share_name}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if stored_be_filesystem_name != be_filesystem_name:
            msg = _("Filesystem Name does not match between stored FE and "
                    "Alletra BE Share. FE Stored: %(fe_val)s BE: "
                    "%(be_val)s") % {'fe_val': stored_be_filesystem_name,
                                     'be_val': be_filesystem_name}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if stored_be_sharesetting_name != be_sharesetting_name:
            msg = _("Sharesetting Name does not match between stored FE and "
                    "Alletra BE Share. FE Stored: %(fe_val)s BE: "
                    "%(be_val)s") % {'fe_val': stored_be_sharesetting_name,
                                     'be_val': be_sharesetting_name}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

    # Edit fileshare by uid
    def validate_edit_fileshare_fe_req(
            self,
            be_fileshare_uid,
            extra_specs,
            expand_filesystem,
            fe_existing_size,
            fe_new_size,
            be_existing_filesystem_size,
            update_access_rules,
            fe_new_access_rules):

        if be_fileshare_uid is None:
            msg = _("Received empty value for BE Fileshare ID from FE")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if not expand_filesystem and not update_access_rules:
            msg = _("One parameter in expand_filesystem/update_access_rules"
                    " is mandatory for Edit Fileshare")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if expand_filesystem:
            self._validate_filesystem_edit_fileshare_fe_req(
                fe_existing_size, fe_new_size, be_existing_filesystem_size)

        if update_access_rules:
            self._validate_sharesettings_edit_fileshare_fe_req(
                extra_specs, fe_new_access_rules)

        # Validate Share Type Values
        self._validate_share_type_extra_specs(extra_specs)

    def _validate_filesystem_edit_fileshare_fe_req(
            self, fe_existing_size, fe_new_size, be_existing_filesystem_size):
        # Validate Expand Filesystem Values

        if fe_existing_size is None:
            msg = _("Received empty value for existing size from FE")
            LOG.error(msg)
            raise exception.InvalidInput(msg)
        fe_existing_size_mib = fe_existing_size * 1024

        if fe_new_size is None:
            msg = _("Received empty value for new share size from FE")
            LOG.error(msg)
            raise exception.InvalidInput(msg)
        fe_new_size_mib = fe_new_size * 1024

        if be_existing_filesystem_size is None:
            msg = _("Received empty value for existing share size from BE")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        # Validate existing values
        if fe_existing_size_mib != be_existing_filesystem_size:
            msg = _(
                "The existing FE Filesystem size does not match with backend "
                "filesystem size. FE Size: %(fe_size)s "
                "BE Size: %(be_size)s") % {
                'fe_size': fe_existing_size_mib,
                'be_size': be_existing_filesystem_size}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        # Validate new size
        if fe_new_size_mib <= fe_existing_size_mib:
            msg = _(
                "The new FE Filesystem size is <= the existing size "
                "FE existing Size: %(fe_existing_size)s FE New "
                "Size: %(fe_new_size)s") % {
                'fe_existing_size': fe_existing_size_mib,
                'fe_new_size': fe_new_size_mib}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        # Validate filesystem expand (size_increase) constraints
        size_increase_mib = (fe_new_size - fe_existing_size) * 1024
        min_expand_mib = constants.BE_MIN_FILESYSTEM_EXPAND_SIZE_MiB
        max_size_gb = constants.BE_MAX_FILESYSTEM_SIZE_GiB

        if size_increase_mib < min_expand_mib:
            msg = _(
                "Filesystem expand size must be at least "
                "%(min_expand)s MB (256 MB). "
                "Requested expand: %(requested)s MB") % {
                'min_expand': min_expand_mib,
                'requested': size_increase_mib}
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if fe_new_size > max_size_gb:
            msg = _("Filesystem size must not exceed %(max_size)s GB "
                    "(64 TB). Requested new size: %(requested)s GB") % {
                'max_size': max_size_gb, 'requested': fe_new_size}
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        # Manila will validate that the parameter is an integer within
        # available capacity of the backend array

    def _validate_sharesettings_edit_fileshare_fe_req(
            self, extra_specs, fe_new_access_rules):

        supported_access_rule_types = ["ip"]
        for access_rule in fe_new_access_rules:
            if access_rule['access_type'] not in supported_access_rule_types:
                msg = _('Access rule type %(access_rule_type)s is not '
                        'supported by this driver') % {
                    'access_rule_type': access_rule['access_type']}
                raise exception.OperationNotSupportedByDriverMode(msg)

            # Manila already validates the input IP is passed in
            # one of the two formats XX.XX.XX.XX or XX.XX.XX.XX/XX

        squash_option = extra_specs.get('hpe_alletra_b10000:squash_option')
        self._validate_share_type_squash_option_value(squash_option)

    # Manage fileshare
    def validate_manage_fileshare_fe_req(self, fe_fileshare, extra_specs):
        # Validate share protocol
        if 'share_proto' not in fe_fileshare:
            msg = _(
                "Did not receive share_proto parameter from "
                "manage_fileshare fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if fe_fileshare['share_proto'].upper() != 'NFS':
            msg = _("Protocol %(protocol)s is not supported. "
                    "This driver only supports NFS protocol.") % {
                        'protocol': fe_fileshare['share_proto']}
            LOG.error(msg)
            raise exception.ManageInvalidShare(reason=msg)

        if 'export_locations' not in fe_fileshare:
            msg = _(
                "Did not receive export_locations parameter from "
                "manage_fileshare fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if len(fe_fileshare['export_locations']) == 0:
            msg = _(
                "Received empty export_locations list from "
                "manage_fileshare fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if len(fe_fileshare['export_locations']) > 1:
            msg = _(
                "Received more than 1 value in export_locations list "
                "from manage_fileshare fe request."
                "Alletra B10000 driver does not suppot this")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if 'path' not in fe_fileshare['export_locations'][0]:
            msg = _(
                "Did not receive path parameter as part of export_locations "
                "from manage_fileshare fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        export_path = fe_fileshare['export_locations'][0]['path']

        if ':' not in export_path:
            msg = _("Export path must be in format IP:/path/to/share")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        path_parts = export_path.split(':', 1)  # Split into at most 2 parts
        ip_address, mount_path = path_parts

        if not ip_address or not mount_path:
            msg = _("Both IP address and mount path must be "
                    "provided in export path")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if not utils.is_valid_ip_address(ip_address, '4'):
            msg = (
                _("IP address (%s) is invalid. Only IPv4 addresses "
                  "are supported.") % ip_address)
            LOG.error(msg)
            raise exception.InvalidInput(reason=msg)

        # Mount path current format: /file/{filesystemname}/{sharename}
        if not mount_path.startswith('/file/'):
            msg = _(
                "Mount path must start with '/file/'. Received: "
                "%(path)s") % {'path': mount_path}
            LOG.error(msg)
            raise exception.InvalidInput(reason=msg)

        path_components = mount_path.split('/')
        # Expected: ['', 'file', 'filesystemname', 'sharename']
        if len(path_components) != 4:
            msg = _("Mount path must be in format "
                    "/file/{filesystemname}/{sharename}. "
                    "Received: %(path)s") % {'path': mount_path}
            LOG.error(msg)
            raise exception.InvalidInput(reason=msg)

        # Manila will validate that no 2 shares have the same export_path.
        # We don't need to validate managing the same share twice scenario

        # Validate Share Type Values
        self._validate_share_type_extra_specs(extra_specs)

    def _is_default_clientinfo(self, clientinfo):
        """Check if clientinfo matches the default secure access rule.

        Validates that clientinfo is a list with exactly one element
        containing the default values from constants.
        """
        if not isinstance(clientinfo, list) or len(clientinfo) != 1:
            return False

        rule = clientinfo[0]
        return (rule.get('ipaddress') == constants.DEFAULT_IP_1 and
                rule.get('access') == constants.DEFAULT_ACCESS_LEVEL_1 and
                rule.get('options') == constants.DEFAULT_SQUASH_OPTION_1)

    # Share Type Validations - Used for Create, Edit, Manage
    def _validate_share_type_extra_specs(self, extra_specs):
        squash_option = extra_specs.get('hpe_alletra_b10000:squash_option')
        self._validate_share_type_squash_option_value(squash_option)

        reduce_str = extra_specs.get('hpe_alletra_b10000:reduce')
        self._validate_share_type_reduce_value(reduce_str)

        dedupe_str = extra_specs.get('dedupe')
        self._validate_share_type_dedupe_value(dedupe_str)

        compression_str = extra_specs.get('compression')
        self._validate_share_type_compression_value(compression_str)

        self._validate_share_type_dedupe_compression_comb_values(
            dedupe_str, compression_str)
        self._validate_share_type_reduce_dedupe_compression_conflict(
            reduce_str, dedupe_str, compression_str)

        thin_provisioning_str = extra_specs.get('thin_provisioning')
        self._validate_share_type_thin_prov_value(thin_provisioning_str)

    def _validate_share_type_dedupe_compression_comb_values(
            self, dedupe_str, compression_str):

        if ((dedupe_str is not None and compression_str is None) or
                (dedupe_str is None and compression_str is not None)):
            msg = (
                "The keys dedupe and compression from share type must "
                "both be specified together or both not specified. "
                "Dedupe: %(dedupe)s, Compression: %(compression)s") % {
                'dedupe': dedupe_str,
                'compression': compression_str}
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if dedupe_str is not None and compression_str is not None:
            if dedupe_str.lower() != compression_str.lower():
                msg = _(
                    "The keys dedupe and compression from share type must "
                    "have the same value (both true or both false). "
                    "Dedupe: %(dedupe)s, Compression: %(compression)s") % {
                    'dedupe': dedupe_str,
                    'compression': compression_str}
                LOG.error(msg)
                raise exception.InvalidInput(msg)

    def _validate_share_type_reduce_value(self, reduce_str):
        if reduce_str is not None:
            if reduce_str.lower() not in ('true', 'false'):
                msg = _(
                    "The key hpe_alletra_b10000:reduce from share type must"
                    " have one of the supported values (true, false). "
                    "Value present: %(value)s") % {
                    'value': reduce_str.lower()}
                LOG.error(msg)
                raise exception.InvalidInput(msg)

    def _validate_share_type_squash_option_value(self, squash_option):
        if squash_option is not None:
            supported_squash_values = (
                'root_squash', 'no_root_squash', 'all_squash')
            if squash_option.lower() not in supported_squash_values:
                msg = _(
                    "The key hpe_alletra_b10000:squash_option from share "
                    "type must have one of the supported values "
                    "%(supported)s. Value present: %(actual)s") % {
                    'supported': supported_squash_values,
                    'actual': squash_option.lower()}
                LOG.error(msg)
                raise exception.InvalidInput(msg)

    def _validate_share_type_dedupe_value(self, dedupe_str):
        if dedupe_str is not None:
            if dedupe_str.lower() not in ('true', 'false'):
                msg = _(
                    "The key dedupe from share type must"
                    " have one of the supported values (true, false). "
                    "Value present: %(value)s") % {
                    'value': dedupe_str.lower()}
                LOG.error(msg)
                raise exception.InvalidInput(msg)

    def _validate_share_type_compression_value(self, compression_str):
        if compression_str is not None:
            if compression_str.lower() not in ('true', 'false'):
                msg = _(
                    "The key compression from share type must"
                    " have one of the supported values (true, false). "
                    "Value present: %(value)s") % {
                    'value': compression_str.lower()}
                LOG.error(msg)
                raise exception.InvalidInput(msg)

    def _validate_share_type_thin_prov_value(self, thin_provisioning_str):
        if thin_provisioning_str is not None:
            if thin_provisioning_str.lower() != 'true':
                msg = _(
                    "The key thin_provisioning from share type must "
                    "be 'true' or not specified. "
                    "Value present: %(value)s") % {
                    'value': thin_provisioning_str.lower()}
                LOG.error(msg)
                raise exception.InvalidInput(msg)

    def _validate_share_type_reduce_dedupe_compression_conflict(
            self, reduce_str, dedupe_str, compression_str):
        if ((reduce_str is not None) and
                (dedupe_str is not None or
                 compression_str is not None)):
            msg = (
                "If hpe_alletra_b10000:reduce key is provided, "
                "individual keys compression and dedupe must "
                "not be provided. Reduce: %(reduce)s Dedupe: %(dedupe)s "
                "Compression: %(compression)s") % {
                'reduce': reduce_str,
                'dedupe': dedupe_str,
                'compression': compression_str}
            LOG.error(msg)
            raise exception.InvalidInput(msg)
