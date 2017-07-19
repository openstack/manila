# Copyright (c) 2016 Dell Inc. or its subsidiaries.
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
import re

from lxml import builder
from lxml import etree as ET
from oslo_concurrency import processutils
from oslo_log import log
import six

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.common.enas import connector
from manila.share.drivers.dell_emc.common.enas import constants
from manila.share.drivers.dell_emc.common.enas import utils as vmax_utils
from manila.share.drivers.dell_emc.common.enas import xml_api_parser as parser
from manila import utils

LOG = log.getLogger(__name__)


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class StorageObjectManager(object):
    def __init__(self, configuration):
        self.context = {}

        self.connectors = {}
        self.connectors['XML'] = connector.XMLAPIConnector(configuration)
        self.connectors['SSH'] = connector.SSHConnector(configuration)

        elt_maker = builder.ElementMaker(nsmap={None: constants.XML_NAMESPACE})
        xml_parser = parser.XMLAPIParser()

        obj_types = StorageObject.__subclasses__()  # pylint: disable=E1101
        for item in obj_types:
            key = item.__name__
            self.context[key] = eval(key)(self.connectors,
                                          elt_maker,
                                          xml_parser,
                                          self)

    def getStorageContext(self, type):
        if type in self.context:
            return self.context[type]
        else:
            message = (_("Invalid storage object type %s.") % type)
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)


class StorageObject(object):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        self.conn = conn
        self.elt_maker = elt_maker
        self.xml_parser = xml_parser
        self.manager = manager
        self.xml_retry = False
        self.ssh_retry_patterns = [
            (
                constants.SSH_DEFAULT_RETRY_PATTERN,
                exception.EMCVmaxLockRequiredException()
            ),
        ]

    def _translate_response(self, response):
        """Translate different status to ok/error status."""
        if (constants.STATUS_OK == response['maxSeverity'] or
                constants.STATUS_ERROR == response['maxSeverity']):
            return

        old_Severity = response['maxSeverity']
        if response['maxSeverity'] in (constants.STATUS_DEBUG,
                                       constants.STATUS_INFO):
            response['maxSeverity'] = constants.STATUS_OK

            LOG.warning("Translated status from %(old)s to %(new)s. "
                        "Message: %(info)s.",
                        {'old': old_Severity,
                         'new': response['maxSeverity'],
                         'info': response})

    def _response_validation(self, response, error_code):
        """Validates whether a response includes a certain error code."""
        msg_codes = self._get_problem_message_codes(response['problems'])

        for code in msg_codes:
            if code == error_code:
                return True

        return False

    def _get_problem_message_codes(self, problems):
        message_codes = []
        for problem in problems:
            if 'messageCode' in problem:
                message_codes.append(problem['messageCode'])

        return message_codes

    def _get_problem_messages(self, problems):
        messages = []
        for problem in problems:
            if 'message' in problem:
                messages.append(problem['message'])

        return messages

    def _get_problem_diags(self, problems):
        diags = []

        for problem in problems:
            if 'Diagnostics' in problem:
                diags.append(problem['Diagnostics'])

        return diags

    def _build_query_package(self, body):
        return self.elt_maker.RequestPacket(
            self.elt_maker.Request(
                self.elt_maker.Query(body)
            )
        )

    def _build_task_package(self, body):
        return self.elt_maker.RequestPacket(
            self.elt_maker.Request(
                self.elt_maker.StartTask(body, timeout='300')
            )
        )

    @utils.retry(exception.EMCVmaxLockRequiredException)
    def _send_request(self, req):
        req_xml = constants.XML_HEADER + ET.tostring(req).decode('utf-8')

        rsp_xml = self.conn['XML'].request(str(req_xml))

        response = self.xml_parser.parse(rsp_xml)

        self._translate_response(response)

        if (response['maxSeverity'] != constants.STATUS_OK and
                self._response_validation(response,
                                          constants.MSG_CODE_RETRY)):
            raise exception.EMCVmaxLockRequiredException

        return response

    @utils.retry(exception.EMCVmaxLockRequiredException)
    def _execute_cmd(self, cmd, retry_patterns=None, check_exit_code=False):
        """Execute NAS command via SSH.

        :param retry_patterns: list of tuples,where each tuple contains a reg
            expression and an exception.
        :param check_exit_code: Boolean. Raise
            processutils.ProcessExecutionError if the command failed to
            execute and this parameter is set to True.
        """
        if retry_patterns is None:
            retry_patterns = self.ssh_retry_patterns

        try:
            out, err = self.conn['SSH'].run_ssh(cmd, check_exit_code)
        except processutils.ProcessExecutionError as e:
            for pattern in retry_patterns:
                if re.search(pattern[0], e.stdout):
                    raise pattern[1]

            raise

        return out, err

    def _copy_properties(self, source, target, property_map, deep_copy=True):
        for prop in property_map:
            if isinstance(prop, tuple):
                target_key, src_key = prop
            else:
                target_key = src_key = prop

            if src_key in source:
                if deep_copy and isinstance(source[src_key], list):
                    target[target_key] = copy.deepcopy(source[src_key])
                else:
                    target[target_key] = source[src_key]
            else:
                target[target_key] = None

    def _get_mover_id(self, mover_name, is_vdm):
        if is_vdm:
            return self.get_context('VDM').get_id(mover_name)
        else:
            return self.get_context('Mover').get_id(mover_name,
                                                    self.xml_retry)

    def get_context(self, type):
        return self.manager.getStorageContext(type)


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class FileSystem(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(FileSystem, self).__init__(conn, elt_maker, xml_parser, manager)
        self.filesystem_map = {}

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def create(self, name, size, pool_name, mover_name, is_vdm=True):
        pool_id = self.get_context('StoragePool').get_id(pool_name)

        mover_id = self._get_mover_id(mover_name, is_vdm)
        if is_vdm:
            mover = self.elt_maker.Vdm(vdm=mover_id)
        else:
            mover = self.elt_maker.Mover(mover=mover_id)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_task_package(
            self.elt_maker.NewFileSystem(
                mover,
                self.elt_maker.StoragePool(
                    pool=pool_id,
                    size=six.text_type(size),
                    mayContainSlices='true'
                ),
                name=name
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif self._response_validation(
                response, constants.MSG_FILESYSTEM_EXIST):
            LOG.warning("File system %s already exists. "
                        "Skip the creation.", name)
            return
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to create file system %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    def get(self, name):
        if name not in self.filesystem_map:
            request = self._build_query_package(
                self.elt_maker.FileSystemQueryParams(
                    self.elt_maker.AspectSelection(
                        fileSystems='true',
                        fileSystemCapacityInfos='true'
                    ),
                    self.elt_maker.Alias(name=name)
                )
            )

            response = self._send_request(request)

            if constants.STATUS_OK != response['maxSeverity']:
                if self._is_filesystem_nonexistent(response):
                    return constants.STATUS_NOT_FOUND, response['problems']
                else:
                    return response['maxSeverity'], response['problems']

            if not response['objects']:
                return constants.STATUS_NOT_FOUND, response['problems']

            src = response['objects'][0]
            filesystem = {}
            property_map = (
                'name',
                ('pools_id', 'storagePools'),
                ('volume_id', 'volume'),
                ('size', 'volumeSize'),
                ('id', 'fileSystem'),
                'type',
                'dataServicePolicies',
            )

            self._copy_properties(src, filesystem, property_map)

            self.filesystem_map[name] = filesystem

        return constants.STATUS_OK, self.filesystem_map[name]

    def delete(self, name):
        status, out = self.get(name)
        if constants.STATUS_NOT_FOUND == status:
            LOG.warning("File system %s not found. Skip the deletion.",
                        name)
            return
        elif constants.STATUS_OK != status:
            message = (_("Failed to get file system by name %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': out})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        enas_id = self.filesystem_map[name]['id']

        request = self._build_task_package(
            self.elt_maker.DeleteFileSystem(fileSystem=enas_id)
        )

        response = self._send_request(request)

        if constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to delete file system %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        self.filesystem_map.pop(name)

    def extend(self, name, pool_name, new_size):
        status, out = self.get(name)
        if constants.STATUS_OK != status:
            message = (_("Failed to get file system by name %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': out})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        enas_id = out['id']
        size = int(out['size'])
        if new_size < size:
            message = (_("Failed to extend file system %(name)s because new "
                         "size %(new_size)d is smaller than old size "
                         "%(size)d.") %
                       {'name': name, 'new_size': new_size, 'size': size})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)
        elif new_size == size:
            return

        pool_id = self.get_context('StoragePool').get_id(pool_name)

        request = self._build_task_package(
            self.elt_maker.ExtendFileSystem(
                self.elt_maker.StoragePool(
                    pool=pool_id,
                    size=six.text_type(new_size - size)
                ),
                fileSystem=enas_id,
            )
        )

        response = self._send_request(request)

        if constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to extend file system %(name)s to new size "
                         "%(new_size)d. Reason: %(err)s.") %
                       {'name': name,
                        'new_size': new_size,
                        'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    def get_id(self, name):
        status, out = self.get(name)
        if constants.STATUS_OK != status:
            message = (_("Failed to get file system by name %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': out})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        return self.filesystem_map[name]['id']

    def _is_filesystem_nonexistent(self, response):
        """Translate different status to ok/error status."""
        msg_codes = self._get_problem_message_codes(response['problems'])
        diags = self._get_problem_diags(response['problems'])

        for code, diagnose in zip(msg_codes, diags):
            if (code == constants.MSG_FILESYSTEM_NOT_FOUND and
                    diagnose.find('File system not found.') != -1):
                return True

        return False

    def create_from_snapshot(self, name, snap_name, source_fs_name, pool_name,
                             mover_name, connect_id):
        create_fs_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
            '-name', name,
            '-type', 'uxfs',
            '-create',
            'samesize=' + source_fs_name,
            'pool=%s' % pool_name,
            'storage=SINGLE',
            'worm=off',
            '-thin', 'no',
            '-option', 'slice=y',
        ]

        self._execute_cmd(create_fs_cmd)

        ro_mount_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_mount', mover_name,
            '-option', 'ro',
            name,
            '/%s' % name,
        ]
        self._execute_cmd(ro_mount_cmd)

        session_name = name + ':' + snap_name
        copy_ckpt_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_copy',
            '-name', session_name[0:63],
            '-source', '-ckpt', snap_name,
            '-destination', '-fs', name,
            '-interconnect',
            'id=%s' % connect_id,
            '-overwrite_destination',
            '-full_copy',
        ]

        try:
            self._execute_cmd(copy_ckpt_cmd, check_exit_code=True)
        except processutils.ProcessExecutionError as expt:
            LOG.error("Failed to copy content from snapshot %(snap)s to "
                      "file system %(filesystem)s. Reason: %(err)s.",
                      {'snap': snap_name,
                       'filesystem': name,
                       'err': expt})

        # When an error happens during nas_copy, we need to continue
        # deleting the checkpoint of the target file system if it exists.
        query_fs_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
            '-info', name,
        ]
        out, err = self._execute_cmd(query_fs_cmd)
        re_ckpts = r'ckpts\s*=\s*(.*)\s*'
        m = re.search(re_ckpts, out)
        if m is not None:
            ckpts = m.group(1)
            for ckpt in re.split(',', ckpts):
                umount_ckpt_cmd = [
                    'env', 'NAS_DB=/nas',
                    '/nas/bin/server_umount', mover_name,
                    '-perm', ckpt,
                ]
                self._execute_cmd(umount_ckpt_cmd)
                delete_ckpt_cmd = [
                    'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
                    '-delete', ckpt,
                    '-Force',
                ]
                self._execute_cmd(delete_ckpt_cmd)

        rw_mount_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_mount', mover_name,
            '-option', 'rw',
            name,
            '/%s' % name,
        ]
        self._execute_cmd(rw_mount_cmd)


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class StoragePool(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(StoragePool, self).__init__(conn, elt_maker, xml_parser, manager)
        self.pool_map = {}

    def get(self, name, force=False):
        if name not in self.pool_map or force:
            status, out = self.get_all()
            if constants.STATUS_OK != status:
                return status, out

        if name not in self.pool_map:
            return constants.STATUS_NOT_FOUND, None

        return constants.STATUS_OK, self.pool_map[name]

    def get_all(self):
        self.pool_map.clear()

        request = self._build_query_package(
            self.elt_maker.StoragePoolQueryParams()
        )

        response = self._send_request(request)

        if constants.STATUS_OK != response['maxSeverity']:
            return response['maxSeverity'], response['problems']

        if not response['objects']:
            return constants.STATUS_NOT_FOUND, response['problems']

        for item in response['objects']:
            pool = {}
            property_map = (
                'name',
                ('movers_id', 'movers'),
                ('total_size', 'autoSize'),
                ('used_size', 'usedSize'),
                'diskType',
                'dataServicePolicies',
                ('id', 'pool'),
            )
            self._copy_properties(item, pool, property_map)
            self.pool_map[item['name']] = pool

        return constants.STATUS_OK, self.pool_map

    def get_id(self, name):
        status, out = self.get(name)

        if constants.STATUS_OK != status:
            message = (_("Failed to get storage pool by name %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': out})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        return out['id']


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class MountPoint(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(MountPoint, self).__init__(conn, elt_maker, xml_parser, manager)

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def create(self, mount_path, fs_name, mover_name, is_vdm=True):
        fs_id = self.get_context('FileSystem').get_id(fs_name)

        mover_id = self._get_mover_id(mover_name, is_vdm)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_task_package(
            self.elt_maker.NewMount(
                self.elt_maker.MoverOrVdm(
                    mover=mover_id,
                    moverIdIsVdm='true' if is_vdm else 'false',
                ),
                fileSystem=fs_id,
                path=mount_path
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif self._is_mount_point_already_existent(response):
            LOG.warning("Mount Point %(mount)s already exists. "
                        "Skip the creation.", {'mount': mount_path})
            return
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_('Failed to create Mount Point %(mount)s for '
                         'file system %(fs_name)s. Reason: %(err)s.') %
                       {'mount': mount_path,
                        'fs_name': fs_name,
                        'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def get(self, mover_name, is_vdm=True):
        mover_id = self._get_mover_id(mover_name, is_vdm)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_query_package(
            self.elt_maker.MountQueryParams(
                self.elt_maker.MoverOrVdm(
                    mover=mover_id,
                    moverIdIsVdm='true' if is_vdm else 'false'
                )
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif constants.STATUS_OK != response['maxSeverity']:
            return response['maxSeverity'], response['objects']

        if not response['objects']:
            return constants.STATUS_NOT_FOUND, None
        else:
            return constants.STATUS_OK, response['objects']

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def delete(self, mount_path, mover_name, is_vdm=True):
        mover_id = self._get_mover_id(mover_name, is_vdm)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_task_package(
            self.elt_maker.DeleteMount(
                mover=mover_id,
                moverIdIsVdm='true' if is_vdm else 'false',
                path=mount_path
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif self._is_mount_point_nonexistent(response):
            LOG.warning('Mount point %(mount)s on mover %(mover_name)s '
                        'not found.',
                        {'mount': mount_path, 'mover_name': mover_name})

            return
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_('Failed to delete mount point %(mount)s on mover '
                         '%(mover_name)s. Reason: %(err)s.') %
                       {'mount': mount_path,
                        'mover_name': mover_name,
                        'err': response})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    def _is_mount_point_nonexistent(self, response):
        """Translate different status to ok/error status."""
        msg_codes = self._get_problem_message_codes(response['problems'])
        message = self._get_problem_messages(response['problems'])

        for code, msg in zip(msg_codes, message):
            if ((code == constants.MSG_GENERAL_ERROR and msg.find(
                    'No such path or invalid operation') != -1) or
                    code == constants.MSG_INVALID_VDM_ID or
                    code == constants.MSG_INVALID_MOVER_ID):
                return True

        return False

    def _is_mount_point_already_existent(self, response):
        """Translate different status to ok/error status."""
        msg_codes = self._get_problem_message_codes(response['problems'])
        message = self._get_problem_messages(response['problems'])

        for code, msg in zip(msg_codes, message):
            if ((code == constants.MSG_GENERAL_ERROR and msg.find(
                    'Mount already exists') != -1)):
                return True

        return False


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class Mover(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(Mover, self).__init__(conn, elt_maker, xml_parser, manager)
        self.mover_map = {}
        self.mover_ref_map = {}

    def get_ref(self, name, force=False):
        if name not in self.mover_ref_map or force:
            self.mover_ref_map.clear()

            request = self._build_query_package(
                self.elt_maker.MoverQueryParams(
                    self.elt_maker.AspectSelection(movers='true')
                )
            )

            response = self._send_request(request)

            if constants.STATUS_ERROR == response['maxSeverity']:
                return response['maxSeverity'], response['problems']

            for item in response['objects']:
                mover = {}
                property_map = ('name', ('id', 'mover'))
                self._copy_properties(item, mover, property_map)
                if mover:
                    self.mover_ref_map[mover['name']] = mover

        if (name not in self.mover_ref_map or
                self.mover_ref_map[name]['id'] == ''):
            return constants.STATUS_NOT_FOUND, None

        return constants.STATUS_OK, self.mover_ref_map[name]

    def get(self, name, force=False):
        if name not in self.mover_map or force:
            if name in self.mover_ref_map and not force:
                mover_id = self.mover_ref_map[name]['id']
            else:
                mover_id = self.get_id(name, force)

            if name in self.mover_map:
                self.mover_map.pop(name)

            request = self._build_query_package(
                self.elt_maker.MoverQueryParams(
                    self.elt_maker.AspectSelection(
                        moverDeduplicationSettings='true',
                        moverDnsDomains='true',
                        moverInterfaces='true',
                        moverNetworkDevices='true',
                        moverNisDomains='true',
                        moverRoutes='true',
                        movers='true',
                        moverStatuses='true'
                    ),
                    mover=mover_id
                )
            )

            response = self._send_request(request)
            if constants.STATUS_ERROR == response['maxSeverity']:
                return response['maxSeverity'], response['problems']

            if not response['objects']:
                return constants.STATUS_NOT_FOUND, response['problems']

            mover = {}
            src = response['objects'][0]
            property_map = (
                'name',
                ('id', 'mover'),
                ('Status', 'maxSeverity'),
                'version',
                'uptime',
                'role',
                ('interfaces', 'MoverInterface'),
                ('devices', 'LogicalNetworkDevice'),
                ('dns_domain', 'MoverDnsDomain'),
            )

            self._copy_properties(src, mover, property_map)

            internal_devices = []
            if mover['interfaces']:
                for interface in mover['interfaces']:
                    if self._is_internal_device(interface['device']):
                        internal_devices.append(interface)

                mover['interfaces'] = [var for var in mover['interfaces'] if
                                       var not in internal_devices]

            self.mover_map[name] = mover

        return constants.STATUS_OK, self.mover_map[name]

    def get_id(self, name, force=False):
        status, mover_ref = self.get_ref(name, force)
        if constants.STATUS_OK != status:
            message = (_("Failed to get mover by name %(name)s.") %
                       {'name': name})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        return mover_ref['id']

    def _is_internal_device(self, device):
        for device_type in ('mge', 'fxg', 'tks', 'fsn'):
            if device.find(device_type) == 0:
                return True
        return False

    def get_interconnect_id(self, source, destination):
        header = [
            'id',
            'name',
            'source_server',
            'destination_system',
            'destination_server',
        ]

        conn_id = None

        command_nas_cel = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_cel',
            '-interconnect', '-l',
        ]
        out, err = self._execute_cmd(command_nas_cel)

        lines = out.strip().split('\n')
        for line in lines:
            if line.strip().split() == header:
                LOG.info('Found the header of the command '
                         '/nas/bin/nas_cel -interconnect -l.')
            else:
                interconn = line.strip().split()
                if interconn[2] == source and interconn[4] == destination:
                    conn_id = interconn[0]

        return conn_id

    def get_physical_devices(self, mover_name):

        physical_network_devices = []

        cmd_sysconfig = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_sysconfig', mover_name,
            '-pci'
        ]

        out, err = self._execute_cmd(cmd_sysconfig)

        re_pattern = ('0:\s*(?P<name>\S+)\s*IRQ:\s*(?P<irq>\d+)\n'
                      '.*\n'
                      '\s*Link:\s*(?P<link>[A-Za-z]+)')

        for device in re.finditer(re_pattern, out):
            if 'Up' in device.group('link'):
                physical_network_devices.append(device.group('name'))

        return physical_network_devices


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class VDM(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(VDM, self).__init__(conn, elt_maker, xml_parser, manager)
        self.vdm_map = {}

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def create(self, name, mover_name):
        mover_id = self._get_mover_id(mover_name, False)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_task_package(
            self.elt_maker.NewVdm(mover=mover_id, name=name)
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif self._response_validation(response, constants.MSG_VDM_EXIST):
            LOG.warning("VDM %(name)s already exists. Skip the creation.",
                        {'name': name})
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to create VDM %(name)s on mover "
                         "%(mover_name)s. Reason: %(err)s.") %
                       {'name': name,
                        'mover_name': mover_name,
                        'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    def get(self, name):
        if name not in self.vdm_map:
            request = self._build_query_package(
                self.elt_maker.VdmQueryParams()
            )

            response = self._send_request(request)

            if constants.STATUS_OK != response['maxSeverity']:
                return response['maxSeverity'], response['problems']
            elif not response['objects']:
                return constants.STATUS_NOT_FOUND, response['problems']

            for item in response['objects']:
                vdm = {}
                property_map = (
                    'name',
                    ('id', 'vdm'),
                    'state',
                    ('host_mover_id', 'mover'),
                    ('interfaces', 'Interfaces'),
                )
                self._copy_properties(item, vdm, property_map)
                self.vdm_map[item['name']] = vdm

        if name not in self.vdm_map:
            return constants.STATUS_NOT_FOUND, None

        return constants.STATUS_OK, self.vdm_map[name]

    def delete(self, name):
        status, out = self.get(name)
        if constants.STATUS_NOT_FOUND == status:
            LOG.warning("VDM %s not found. Skip the deletion.",
                        name)
            return
        elif constants.STATUS_OK != status:
            message = (_("Failed to get VDM by name %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': out})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        vdm_id = self.vdm_map[name]['id']

        request = self._build_task_package(
            self.elt_maker.DeleteVdm(vdm=vdm_id)
        )

        response = self._send_request(request)

        if constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to delete VDM %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        self.vdm_map.pop(name)

    def get_id(self, name):
        status, vdm = self.get(name)
        if constants.STATUS_OK != status:
            message = (_("Failed to get VDM by name %(name)s.") %
                       {'name': name})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        return vdm['id']

    def attach_nfs_interface(self, vdm_name, if_name):

        command_attach_nfs_interface = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-vdm', vdm_name,
            '-attach', if_name,
        ]

        self._execute_cmd(command_attach_nfs_interface)

    def detach_nfs_interface(self, vdm_name, if_name):

        command_detach_nfs_interface = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-vdm', vdm_name,
            '-detach', if_name,
        ]

        try:
            self._execute_cmd(command_detach_nfs_interface,
                              check_exit_code=True)
        except processutils.ProcessExecutionError:
            interfaces = self.get_interfaces(vdm_name)
            if if_name not in interfaces['nfs']:
                LOG.debug("Failed to detach interface %(interface)s "
                          "from mover %(mover_name)s.",
                          {'interface': if_name, 'mover_name': vdm_name})
            else:
                message = (_("Failed to detach interface %(interface)s "
                             "from mover %(mover_name)s.") %
                           {'interface': if_name, 'mover_name': vdm_name})
                LOG.exception(message)
                raise exception.EMCVmaxXMLAPIError(err=message)

    def get_interfaces(self, vdm_name):
        interfaces = {
            'cifs': [],
            'nfs': [],
        }

        re_pattern = ('Interfaces to services mapping:'
                      '\s*(?P<interfaces>(\s*interface=.*)*)')

        command_get_interfaces = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-i',
            '-vdm', vdm_name,
        ]

        out, err = self._execute_cmd(command_get_interfaces)

        m = re.search(re_pattern, out)
        if m:
            if_list = m.group('interfaces').split('\n')
            for i in if_list:
                m_if = re.search('\s*interface=(?P<if>.*)\s*:'
                                 '\s*(?P<type>.*)\s*', i)
                if m_if:
                    if_name = m_if.group('if').strip()
                    if 'cifs' == m_if.group('type') and if_name != '':
                        interfaces['cifs'].append(if_name)
                    elif (m_if.group('type') in ('vdm', 'nfs')
                          and if_name != ''):
                        interfaces['nfs'].append(if_name)

        return interfaces


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class Snapshot(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(Snapshot, self).__init__(conn, elt_maker, xml_parser, manager)
        self.snap_map = {}

    def create(self, name, fs_name, pool_id, ckpt_size=None):
        fs_id = self.get_context('FileSystem').get_id(fs_name)

        if ckpt_size:
            elt_pool = self.elt_maker.StoragePool(
                pool=pool_id,
                size=six.text_type(ckpt_size)
            )
        else:
            elt_pool = self.elt_maker.StoragePool(pool=pool_id)

        new_ckpt = self.elt_maker.NewCheckpoint(
            self.elt_maker.SpaceAllocationMethod(
                elt_pool
            ),
            checkpointOf=fs_id,
            name=name
        )

        request = self._build_task_package(new_ckpt)

        response = self._send_request(request)

        if self._response_validation(response, constants.MSG_SNAP_EXIST):
            LOG.warning("Snapshot %(name)s already exists. "
                        "Skip the creation.",
                        {'name': name})
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to create snapshot %(name)s on "
                         "filesystem %(fs_name)s. Reason: %(err)s.") %
                       {'name': name,
                        'fs_name': fs_name,
                        'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    def get(self, name):
        if name not in self.snap_map:
            request = self._build_query_package(
                self.elt_maker.CheckpointQueryParams(
                    self.elt_maker.Alias(name=name)
                )
            )

            response = self._send_request(request)

            if constants.STATUS_OK != response['maxSeverity']:
                return response['maxSeverity'], response['problems']

            if not response['objects']:
                return constants.STATUS_NOT_FOUND, response['problems']

            src = response['objects'][0]
            snap = {}
            property_map = (
                'name',
                ('id', 'checkpoint'),
                'checkpointOf',
                'state',
            )
            self._copy_properties(src, snap, property_map)

            self.snap_map[name] = snap

        return constants.STATUS_OK, self.snap_map[name]

    def delete(self, name):
        status, out = self.get(name)
        if constants.STATUS_NOT_FOUND == status:
            LOG.warning("Snapshot %s not found. Skip the deletion.",
                        name)
            return
        elif constants.STATUS_OK != status:
            message = (_("Failed to get snapshot by name %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': out})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        chpt_id = self.snap_map[name]['id']

        request = self._build_task_package(
            self.elt_maker.DeleteCheckpoint(checkpoint=chpt_id)
        )

        response = self._send_request(request)
        if constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to delete snapshot %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        self.snap_map.pop(name)

    def get_id(self, name):
        status, out = self.get(name)

        if constants.STATUS_OK != status:
            message = (_("Failed to get snapshot by %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': out})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        return self.snap_map[name]['id']


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class MoverInterface(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(MoverInterface, self).__init__(conn, elt_maker, xml_parser,
                                             manager)

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def create(self, interface):
        # Maximum of 32 characters for mover interface name
        name = interface['name']
        if len(name) > 32:
            name = name[0:31]

        device_name = interface['device_name']
        ip_addr = interface['ip']
        mover_name = interface['mover_name']
        net_mask = interface['net_mask']
        vlan_id = interface['vlan_id'] if interface['vlan_id'] else -1

        mover_id = self._get_mover_id(mover_name, False)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_task_package(
            self.elt_maker.NewMoverInterface(
                device=device_name,
                ipAddress=six.text_type(ip_addr),
                mover=mover_id,
                name=name,
                netMask=net_mask,
                vlanid=six.text_type(vlan_id)
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif self._response_validation(
                response, constants.MSG_INTERFACE_NAME_EXIST):
            LOG.warning("Mover interface name %s already exists. "
                        "Skip the creation.", name)
        elif self._response_validation(
                response, constants.MSG_INTERFACE_EXIST):
            LOG.warning("Mover interface IP %s already exists. "
                        "Skip the creation.", ip_addr)
        elif self._response_validation(
                response, constants.MSG_INTERFACE_INVALID_VLAN_ID):
            # When fail to create a mover interface with the specified
            # vlan id, VMAX will leave an interface with vlan id 0 in the
            # backend. So we should explicitly remove the interface.
            try:
                self.delete(six.text_type(ip_addr), mover_name)
            except exception.EMCVmaxXMLAPIError:
                pass
            message = (_("Invalid vlan id %s. Other interfaces on this "
                         "subnet are in a different vlan.") % vlan_id)
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to create mover interface %(interface)s. "
                         "Reason: %(err)s.") %
                       {'interface': interface,
                        'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    def get(self, name, mover_name):
        # Maximum of 32 characters for mover interface name
        if len(name) > 32:
            name = name[0:31]

        status, mover = self.manager.getStorageContext('Mover').get(
            mover_name, True)
        if constants.STATUS_OK == status:
            for interface in mover['interfaces']:
                if name == interface['name']:
                    return constants.STATUS_OK, interface

        return constants.STATUS_NOT_FOUND, None

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def delete(self, ip_addr, mover_name):
        mover_id = self._get_mover_id(mover_name, False)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_task_package(
            self.elt_maker.DeleteMoverInterface(
                ipAddress=six.text_type(ip_addr),
                mover=mover_id
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif self._response_validation(
                response, constants.MSG_INTERFACE_NON_EXISTENT):
            LOG.warning("Mover interface %s not found. "
                        "Skip the deletion.", ip_addr)
            return
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to delete mover interface %(ip)s on mover "
                         "%(mover)s. Reason: %(err)s.") %
                       {'ip': ip_addr,
                        'mover': mover_name,
                        'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class DNSDomain(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(DNSDomain, self).__init__(conn, elt_maker, xml_parser, manager)

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def create(self, mover_name, name, servers, protocol='udp'):
        mover_id = self._get_mover_id(mover_name, False)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_task_package(
            self.elt_maker.NewMoverDnsDomain(
                mover=mover_id,
                name=name,
                servers=servers,
                protocol=protocol
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to create DNS domain %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def delete(self, mover_name, name):
        mover_id = self._get_mover_id(mover_name, False)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_task_package(
            self.elt_maker.DeleteMoverDnsDomain(
                mover=mover_id,
                name=name
            )
        )

        response = self._send_request(request)
        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif constants.STATUS_OK != response['maxSeverity']:
            LOG.warning("Failed to delete DNS domain %(name)s. "
                        "Reason: %(err)s.",
                        {'name': name, 'err': response['problems']})


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class CIFSServer(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(CIFSServer, self).__init__(conn, elt_maker, xml_parser, manager)
        self.cifs_server_map = {}

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def create(self, server_args):
        compName = server_args['name']
        # Maximum of 14 characters for netBIOS name
        name = server_args['name'][-14:]
        # Maximum of 12 characters for alias name
        alias_name = server_args['name'][-12:]
        interfaces = server_args['interface_ip']
        domain_name = server_args['domain_name']
        user_name = server_args['user_name']
        password = server_args['password']
        mover_name = server_args['mover_name']
        is_vdm = server_args['is_vdm']

        mover_id = self._get_mover_id(mover_name, is_vdm)

        if self.xml_retry:
            self.xml_retry = False

        alias_name_list = [self.elt_maker.li(alias_name)]

        request = self._build_task_package(
            self.elt_maker.NewW2KCifsServer(
                self.elt_maker.MoverOrVdm(
                    mover=mover_id,
                    moverIdIsVdm='true' if server_args['is_vdm'] else 'false'
                ),
                self.elt_maker.Aliases(*alias_name_list),
                self.elt_maker.JoinDomain(userName=user_name,
                                          password=password),
                compName=compName,
                domain=domain_name,
                interfaces=interfaces,
                name=name
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        if constants.STATUS_OK != response['maxSeverity']:
            status, out = self.get(compName, mover_name, is_vdm)
            if constants.STATUS_OK == status and out['domainJoined'] == 'true':
                return
            else:
                message = (_("Failed to create CIFS server %(name)s. "
                             "Reason: %(err)s.") %
                           {'name': name,
                            'err': response['problems']})
                LOG.error(message)
                raise exception.EMCVmaxXMLAPIError(err=message)

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def get_all(self, mover_name, is_vdm=True):
        mover_id = self._get_mover_id(mover_name, is_vdm)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_query_package(
            self.elt_maker.CifsServerQueryParams(
                self.elt_maker.MoverOrVdm(
                    mover=mover_id,
                    moverIdIsVdm='true' if is_vdm else 'false'
                )
            )
        )

        response = self._send_request(request)
        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif constants.STATUS_OK != response['maxSeverity']:
            return response['maxSeverity'], response['objects']

        if mover_name in self.cifs_server_map:
            self.cifs_server_map.pop(mover_name)

        self.cifs_server_map[mover_name] = {}

        for item in response['objects']:
            self.cifs_server_map[mover_name][item['compName'].lower()] = item

        return constants.STATUS_OK, self.cifs_server_map[mover_name]

    def get(self, name, mover_name, is_vdm=True, force=False):
        # name is compName
        name = name.lower()

        if (mover_name in self.cifs_server_map and
                name in self.cifs_server_map[mover_name]) and not force:
            return constants.STATUS_OK, self.cifs_server_map[mover_name][name]

        self.get_all(mover_name, is_vdm)

        if mover_name in self.cifs_server_map:
            for compName, server in self.cifs_server_map[mover_name].items():
                if name == compName:
                    return constants.STATUS_OK, server

        return constants.STATUS_NOT_FOUND, None

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def modify(self, server_args):
        """Make CIFS server join or un-join the domain.

        :param server_args: Dictionary for CIFS server modification
            name: CIFS server name instead of compName
            join_domain: True for joining the domain, false for un-joining
            user_name: User name under which the domain is joined
            password: Password associated with the user name
            mover_name: mover or VDM name
            is_vdm: Boolean to indicate mover or VDM
        :raises exception.EMCVmaxXMLAPIError: if modification fails.
        """
        name = server_args['name']
        join_domain = server_args['join_domain']
        user_name = server_args['user_name']
        password = server_args['password']
        mover_name = server_args['mover_name']

        if 'is_vdm' in server_args.keys():
            is_vdm = server_args['is_vdm']
        else:
            is_vdm = True

        mover_id = self._get_mover_id(mover_name, is_vdm)

        if self.xml_retry:
            self.xml_retry = False

        request = self._build_task_package(
            self.elt_maker.ModifyW2KCifsServer(
                self.elt_maker.DomainSetting(
                    joinDomain='true' if join_domain else 'false',
                    password=password,
                    userName=user_name,
                ),
                mover=mover_id,
                moverIdIsVdm='true' if is_vdm else 'false',
                name=name
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif self._ignore_modification_error(response, join_domain):
            return
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to modify CIFS server %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name,
                        'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    def _ignore_modification_error(self, response, join_domain):
        if self._response_validation(response, constants.MSG_JOIN_DOMAIN):
            return join_domain
        elif self._response_validation(response, constants.MSG_UNJOIN_DOMAIN):
            return not join_domain

        return False

    def delete(self, computer_name, mover_name, is_vdm=True):
        try:
            status, out = self.get(
                computer_name.lower(), mover_name, is_vdm, self.xml_retry)
            if constants.STATUS_NOT_FOUND == status:
                LOG.warning("CIFS server %(name)s on mover %(mover_name)s "
                            "not found. Skip the deletion.",
                            {'name': computer_name, 'mover_name': mover_name})
                return
        except exception.EMCVmaxXMLAPIError:
            LOG.warning("CIFS server %(name)s on mover %(mover_name)s "
                        "not found. Skip the deletion.",
                        {'name': computer_name, 'mover_name': mover_name})
            return

        server_name = out['name']

        mover_id = self._get_mover_id(mover_name, is_vdm)

        request = self._build_task_package(
            self.elt_maker.DeleteCifsServer(
                mover=mover_id,
                moverIdIsVdm='true' if is_vdm else 'false',
                name=server_name
            )
        )

        response = self._send_request(request)

        if constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to delete CIFS server %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': computer_name, 'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        self.cifs_server_map[mover_name].pop(computer_name)


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class CIFSShare(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(CIFSShare, self).__init__(conn, elt_maker, xml_parser, manager)
        self.cifs_share_map = {}

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def create(self, name, server_name, mover_name, is_vdm=True):
        mover_id = self._get_mover_id(mover_name, is_vdm)

        if self.xml_retry:
            self.xml_retry = False

        share_path = '/' + name

        request = self._build_task_package(
            self.elt_maker.NewCifsShare(
                self.elt_maker.MoverOrVdm(
                    mover=mover_id,
                    moverIdIsVdm='true' if is_vdm else 'false'
                ),
                self.elt_maker.CifsServers(self.elt_maker.li(server_name)),
                name=name,
                path=share_path
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to create file share %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    def get(self, name):
        if name not in self.cifs_share_map:
            request = self._build_query_package(
                self.elt_maker.CifsShareQueryParams(name=name)
            )

            response = self._send_request(request)

            if constants.STATUS_OK != response['maxSeverity']:
                return response['maxSeverity'], response['problems']

            if not response['objects']:
                return constants.STATUS_NOT_FOUND, None

            self.cifs_share_map[name] = response['objects'][0]

        return constants.STATUS_OK, self.cifs_share_map[name]

    @utils.retry(exception.EMCVmaxInvalidMoverID)
    def delete(self, name, mover_name, is_vdm=True):
        status, out = self.get(name)
        if constants.STATUS_NOT_FOUND == status:
            LOG.warning("CIFS share %s not found. Skip the deletion.",
                        name)
            return
        elif constants.STATUS_OK != status:
            message = (_("Failed to get CIFS share by name %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': out})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        mover_id = self._get_mover_id(mover_name, is_vdm)

        if self.xml_retry:
            self.xml_retry = False

        netbios_names = self.cifs_share_map[name]['CifsServers']

        request = self._build_task_package(
            self.elt_maker.DeleteCifsShare(
                self.elt_maker.CifsServers(*map(lambda a: self.elt_maker.li(a),
                                                netbios_names)),
                mover=mover_id,
                moverIdIsVdm='true' if is_vdm else 'false',
                name=name
            )
        )

        response = self._send_request(request)

        if (self._response_validation(response,
                                      constants.MSG_INVALID_MOVER_ID) and
                not self.xml_retry):
            self.xml_retry = True
            raise exception.EMCVmaxInvalidMoverID(id=mover_id)
        elif constants.STATUS_OK != response['maxSeverity']:
            message = (_("Failed to delete file system %(name)s. "
                         "Reason: %(err)s.") %
                       {'name': name, 'err': response['problems']})
            LOG.error(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        self.cifs_share_map.pop(name)

    def disable_share_access(self, share_name, mover_name):
        cmd_str = 'sharesd %s set noaccess' % share_name
        disable_access = [
            'env', 'NAS_DB=/nas', '/nas/bin/.server_config', mover_name,
            '-v', "%s" % cmd_str,
        ]

        try:
            self._execute_cmd(disable_access, check_exit_code=True)
        except processutils.ProcessExecutionError:
            message = (_('Failed to disable the access to CIFS share '
                         '%(name)s.') %
                       {'name': share_name})
            LOG.exception(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    def allow_share_access(self, mover_name, share_name, user_name, domain,
                           access=constants.CIFS_ACL_FULLCONTROL):
        account = user_name + "@" + domain
        allow_str = ('sharesd %(share_name)s grant %(account)s=%(access)s'
                     % {'share_name': share_name,
                        'account': account,
                        'access': access})

        allow_access = [
            'env', 'NAS_DB=/nas', '/nas/bin/.server_config', mover_name,
            '-v', "%s" % allow_str,
        ]

        try:
            self._execute_cmd(allow_access, check_exit_code=True)
        except processutils.ProcessExecutionError as expt:
            dup_msg = re.compile(r'ACE for %(domain)s\\%(user)s unchanged' %
                                 {'domain': domain, 'user': user_name}, re.I)
            if re.search(dup_msg, expt.stdout):
                LOG.warning("Duplicate access control entry, "
                            "skipping allow...")
            else:
                message = (_('Failed to allow the access %(access)s to '
                             'CIFS share %(name)s. Reason: %(err)s.') %
                           {'access': access, 'name': share_name, 'err': expt})
                LOG.error(message)
                raise exception.EMCVmaxXMLAPIError(err=message)

    def deny_share_access(self, mover_name, share_name, user_name, domain,
                          access=constants.CIFS_ACL_FULLCONTROL):
        account = user_name + "@" + domain
        revoke_str = ('sharesd %(share_name)s revoke %(account)s=%(access)s'
                      % {'share_name': share_name,
                         'account': account,
                         'access': access})

        allow_access = [
            'env', 'NAS_DB=/nas', '/nas/bin/.server_config', mover_name,
            '-v', "%s" % revoke_str,
        ]
        try:
            self._execute_cmd(allow_access, check_exit_code=True)
        except processutils.ProcessExecutionError as expt:
            not_found_msg = re.compile(
                r'No ACE found for %(domain)s\\%(user)s'
                % {'domain': domain, 'user': user_name}, re.I)
            user_err_msg = re.compile(
                r'Cannot get mapping for %(domain)s\\%(user)s'
                % {'domain': domain, 'user': user_name}, re.I)

            if re.search(not_found_msg, expt.stdout):
                LOG.warning("No access control entry found, "
                            "skipping deny...")
            elif re.search(user_err_msg, expt.stdout):
                LOG.warning("User not found on domain, skipping deny...")
            else:
                message = (_('Failed to deny the access %(access)s to '
                             'CIFS share %(name)s. Reason: %(err)s.') %
                           {'access': access, 'name': share_name, 'err': expt})
                LOG.exception(message)
                raise exception.EMCVmaxXMLAPIError(err=message)

    def get_share_access(self, mover_name, share_name):
        get_str = 'sharesd %s dump' % share_name
        get_access = [
            'env', 'NAS_DB=/nas', '/nas/bin/.server_config', mover_name,
            '-v', "%s" % get_str,
        ]

        try:
            out, err = self._execute_cmd(get_access, check_exit_code=True)
        except processutils.ProcessExecutionError:
            msg = _('Failed to get access list of CIFS share %s.') % share_name
            LOG.exception(msg)
            raise exception.EMCVmaxXMLAPIError(err=msg)

        ret = {}
        name_pattern = re.compile(r"Unix user '(.+?)'")
        access_pattern = re.compile(r"ALLOWED:(.+?):")

        name = None
        for line in out.splitlines():
            if name is None:
                names = name_pattern.findall(line)
                if names:
                    name = names[0].lower()
            else:
                accesses = access_pattern.findall(line)
                if accesses:
                    ret[name] = accesses[0].lower()
                    name = None
        return ret

    def clear_share_access(self, mover_name, share_name, domain,
                           white_list_users):
        existing_users = self.get_share_access(mover_name, share_name)
        white_list_users_set = set(user.lower() for user in white_list_users)
        users_to_remove = set(existing_users.keys()) - white_list_users_set
        for user in users_to_remove:
            self.deny_share_access(mover_name, share_name, user, domain,
                                   existing_users[user])
        return users_to_remove


@vmax_utils.decorate_all_methods(vmax_utils.log_enter_exit,
                                 debug_only=True)
class NFSShare(StorageObject):
    def __init__(self, conn, elt_maker, xml_parser, manager):
        super(NFSShare, self).__init__(conn, elt_maker, xml_parser, manager)
        self.nfs_share_map = {}

    def create(self, name, mover_name):
        share_path = '/' + name
        create_nfs_share_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-option', 'access=-0.0.0.0/0.0.0.0',
            share_path,
        ]

        try:
            self._execute_cmd(create_nfs_share_cmd, check_exit_code=True)
        except processutils.ProcessExecutionError as expt:
            message = (_('Failed to create NFS share %(name)s on mover '
                         '%(mover_name)s. Reason: %(err)s.') %
                       {'name': name, 'mover_name': mover_name, 'err': expt})
            LOG.exception(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

    def delete(self, name, mover_name):
        path = '/' + name

        status, out = self.get(name, mover_name)
        if constants.STATUS_NOT_FOUND == status:
            LOG.warning("NFS share %s not found. Skip the deletion.",
                        path)
            return

        delete_nfs_share_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-unexport',
            '-perm',
            path,
        ]

        try:
            self._execute_cmd(delete_nfs_share_cmd, check_exit_code=True)
        except processutils.ProcessExecutionError as expt:
            message = (_('Failed to delete NFS share %(name)s on '
                         '%(mover_name)s. Reason: %(err)s.') %
                       {'name': name, 'mover_name': mover_name, 'err': expt})
            LOG.exception(message)
            raise exception.EMCVmaxXMLAPIError(err=message)

        self.nfs_share_map.pop(name)

    def get(self, name, mover_name, force=False, check_exit_code=False):
        if name in self.nfs_share_map and not force:
            return constants.STATUS_OK, self.nfs_share_map[name]

        path = '/' + name

        nfs_share = {
            "mover_name": '',
            "path": '',
            'AccessHosts': [],
            'RwHosts': [],
            'RoHosts': [],
            'RootHosts': [],
            'readOnly': '',
        }

        nfs_query_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-P', 'nfs',
            '-list', path,
        ]

        try:
            out, err = self._execute_cmd(nfs_query_cmd,
                                         check_exit_code=check_exit_code)
        except processutils.ProcessExecutionError as expt:
            dup_msg = (r'%(mover_name)s : No such file or directory' %
                       {'mover_name': mover_name})
            if re.search(dup_msg, expt.stdout):
                LOG.warning("NFS share %s not found.", name)
                return constants.STATUS_NOT_FOUND, None
            else:
                message = (_('Failed to list NFS share %(name)s on '
                             '%(mover_name)s. Reason: %(err)s.') %
                           {'name': name,
                            'mover_name': mover_name,
                            'err': expt})
                LOG.exception(message)
                raise exception.EMCVmaxXMLAPIError(err=message)

        re_exports = '%s\s*:\s*\nexport\s*(.*)\n' % mover_name
        m = re.search(re_exports, out)
        if m is not None:
            nfs_share['path'] = path
            nfs_share['mover_name'] = mover_name
            export = m.group(1)
            fields = export.split(" ")
            for field in fields:
                field = field.strip()
                if field.startswith('rw='):
                    nfs_share['RwHosts'] = field[3:].split(":")
                elif field.startswith('access='):
                    nfs_share['AccessHosts'] = field[7:].split(":")
                elif field.startswith('root='):
                    nfs_share['RootHosts'] = field[5:].split(":")
                elif field.startswith('ro='):
                    nfs_share['RoHosts'] = field[3:].split(":")

            self.nfs_share_map[name] = nfs_share
        else:
            return constants.STATUS_NOT_FOUND, None

        return constants.STATUS_OK, self.nfs_share_map[name]

    def allow_share_access(self, share_name, host_ip, mover_name,
                           access_level=const.ACCESS_LEVEL_RW):
        @utils.synchronized('emc-shareaccess-' + share_name)
        def do_allow_access(share_name, host_ip, mover_name, access_level):
            status, share = self.get(share_name, mover_name)
            if constants.STATUS_NOT_FOUND == status:
                message = (_('NFS share %s not found.') % share_name)
                LOG.error(message)
                raise exception.EMCVmaxXMLAPIError(err=message)

            changed = False
            rwhosts = share['RwHosts']
            rohosts = share['RoHosts']
            if access_level == const.ACCESS_LEVEL_RW:
                if host_ip not in rwhosts:
                    rwhosts.append(host_ip)
                    changed = True
                if host_ip in rohosts:
                    rohosts.remove(host_ip)
                    changed = True
            if access_level == const.ACCESS_LEVEL_RO:
                if host_ip not in rohosts:
                    rohosts.append(host_ip)
                    changed = True
                if host_ip in rwhosts:
                    rwhosts.remove(host_ip)
                    changed = True

            roothosts = share['RootHosts']
            if host_ip not in roothosts:
                roothosts.append(host_ip)
                changed = True
            accesshosts = share['AccessHosts']
            if host_ip not in accesshosts:
                accesshosts.append(host_ip)
                changed = True

            if not changed:
                LOG.debug("%(host)s is already in access list of share "
                          "%(name)s.", {'host': host_ip, 'name': share_name})
            else:
                path = '/' + share_name
                self._set_share_access(path,
                                       mover_name,
                                       rwhosts,
                                       rohosts,
                                       roothosts,
                                       accesshosts)

                # Update self.nfs_share_map
                self.get(share_name, mover_name, force=True,
                         check_exit_code=True)

        do_allow_access(share_name, host_ip, mover_name, access_level)

    def deny_share_access(self, share_name, host_ip, mover_name):

        @utils.synchronized('emc-shareaccess-' + share_name)
        def do_deny_access(share_name, host_ip, mover_name):
            status, share = self.get(share_name, mover_name)
            if constants.STATUS_OK != status:
                message = (_('Query nfs share %(path)s failed. '
                             'Reason %(err)s.') %
                           {'path': share_name, 'err': share})
                LOG.error(message)
                raise exception.EMCVmaxXMLAPIError(err=message)

            changed = False
            rwhosts = set(share['RwHosts'])
            if host_ip in rwhosts:
                rwhosts.remove(host_ip)
                changed = True
            roothosts = set(share['RootHosts'])
            if host_ip in roothosts:
                roothosts.remove(host_ip)
                changed = True
            accesshosts = set(share['AccessHosts'])
            if host_ip in accesshosts:
                accesshosts.remove(host_ip)
                changed = True
            rohosts = set(share['RoHosts'])
            if host_ip in rohosts:
                rohosts.remove(host_ip)
                changed = True
            if not changed:
                LOG.debug("%(host)s is already in access list of share "
                          "%(name)s.", {'host': host_ip, 'name': share_name})
            else:
                path = '/' + share_name
                self._set_share_access(path,
                                       mover_name,
                                       rwhosts,
                                       rohosts,
                                       roothosts,
                                       accesshosts)

                # Update self.nfs_share_map
                self.get(share_name, mover_name, force=True,
                         check_exit_code=True)

        do_deny_access(share_name, host_ip, mover_name)

    def clear_share_access(self, share_name, mover_name, white_list_hosts):
        @utils.synchronized('emc-shareaccess-' + share_name)
        def do_clear_access(share_name, mover_name, white_list_hosts):
            def hosts_to_remove(orig_list):
                if white_list_hosts is None:
                    ret = set()
                else:
                    ret = set(white_list_hosts).intersection(set(orig_list))
                return ret

            status, share = self.get(share_name, mover_name)
            if constants.STATUS_OK != status:
                message = (_('Query nfs share %(path)s failed. '
                             'Reason %(err)s.') %
                           {'path': share_name, 'err': status})
                raise exception.EMCVmaxXMLAPIError(err=message)

            self._set_share_access('/' + share_name,
                                   mover_name,
                                   hosts_to_remove(share['RwHosts']),
                                   hosts_to_remove(share['RoHosts']),
                                   hosts_to_remove(share['RootHosts']),
                                   hosts_to_remove(share['AccessHosts']))

            # Update self.nfs_share_map
            self.get(share_name, mover_name, force=True,
                     check_exit_code=True)

        do_clear_access(share_name, mover_name, white_list_hosts)

    def _set_share_access(self, path, mover_name, rw_hosts, ro_hosts,
                          root_hosts, access_hosts):

        if access_hosts is None:
            access_hosts = set()

        if '-0.0.0.0/0.0.0.0' not in access_hosts:
            access_hosts.add('-0.0.0.0/0.0.0.0')

        access_str = ('access=%(access)s'
                      % {'access': ':'.join(access_hosts)})
        if root_hosts:
            access_str += (',root=%(root)s' % {'root': ':'.join(root_hosts)})
        if rw_hosts:
            access_str += ',rw=%(rw)s' % {'rw': ':'.join(rw_hosts)}
        if ro_hosts:
            access_str += ',ro=%(ro)s' % {'ro': ':'.join(ro_hosts)}
        set_nfs_share_access_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-ignore',
            '-option', access_str,
            path,
        ]

        try:
            self._execute_cmd(set_nfs_share_access_cmd, check_exit_code=True)
        except processutils.ProcessExecutionError as expt:
            message = (_('Failed to set NFS share %(name)s access on '
                         '%(mover_name)s. Reason: %(err)s.') %
                       {'name': path[1:],
                        'mover_name': mover_name,
                        'err': expt})
            LOG.exception(message)
            raise exception.EMCVmaxXMLAPIError(err=message)
