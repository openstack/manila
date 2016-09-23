# Copyright 2015 Hewlett Packard Enterprise Development LP
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

import sys

import ddt
import mock
if 'hpe3parclient' not in sys.modules:
    sys.modules['hpe3parclient'] = mock.Mock()

from manila.data import utils as data_utils
from manila import exception
from manila.share.drivers.hpe import hpe_3par_mediator as hpe3parmediator
from manila import test
from manila.tests.share.drivers.hpe import test_hpe_3par_constants as constants
from manila import utils

from oslo_utils import units
import six

CLIENT_VERSION_MIN_OK = hpe3parmediator.MIN_CLIENT_VERSION
TEST_WSAPI_VERSION_STR = '30201292'


@ddt.ddt
class HPE3ParMediatorTestCase(test.TestCase):

    def setUp(self):
        super(HPE3ParMediatorTestCase, self).setUp()

        # Fake utils.execute
        self.mock_object(utils, 'execute', mock.Mock(return_value={}))

        # Fake data_utils.Copy
        class FakeCopy(object):

            def run(self):
                pass

            def get_progress(self):
                return {'total_progress': 100}

        self.mock_copy = self.mock_object(
            data_utils, 'Copy', mock.Mock(return_value=FakeCopy()))

        # This is the fake client to use.
        self.mock_client = mock.Mock()

        # Take over the hpe3parclient module and stub the constructor.
        hpe3parclient = sys.modules['hpe3parclient']
        hpe3parclient.version_tuple = CLIENT_VERSION_MIN_OK

        # Need a fake constructor to return the fake client.
        # This is also be used for constructor error tests.
        self.mock_object(hpe3parclient.file_client, 'HPE3ParFilePersonaClient')
        self.mock_client_constructor = (
            hpe3parclient.file_client.HPE3ParFilePersonaClient
        )
        self.mock_client = self.mock_client_constructor()

        # Set the mediator to use in tests.
        self.mediator = hpe3parmediator.HPE3ParMediator(
            hpe3par_username=constants.USERNAME,
            hpe3par_password=constants.PASSWORD,
            hpe3par_api_url=constants.API_URL,
            hpe3par_debug=constants.EXPECTED_HPE_DEBUG,
            hpe3par_san_ip=constants.EXPECTED_IP_1234,
            hpe3par_san_login=constants.SAN_LOGIN,
            hpe3par_san_password=constants.SAN_PASSWORD,
            hpe3par_san_ssh_port=constants.PORT,
            hpe3par_cifs_admin_access_username=constants.USERNAME,
            hpe3par_cifs_admin_access_password=constants.PASSWORD,
            hpe3par_cifs_admin_access_domain=constants.EXPECTED_CIFS_DOMAIN,
            hpe3par_share_mount_path=constants.EXPECTED_MOUNT_PATH,
            ssh_conn_timeout=constants.TIMEOUT,
            my_ip=constants.EXPECTED_MY_IP)

    def test_mediator_no_client(self):
        """Test missing hpe3parclient error."""

        mock_log = self.mock_object(hpe3parmediator, 'LOG')
        self.mock_object(hpe3parmediator.HPE3ParMediator, 'no_client', None)

        self.assertRaises(exception.HPE3ParInvalidClient,
                          self.mediator.do_setup)

        mock_log.error.assert_called_once_with(mock.ANY)

    def test_mediator_setup_client_init_error(self):
        """Any client init exceptions should result in a ManilaException."""

        self.mock_client_constructor.side_effect = (
            Exception('Any exception.  E.g., bad version or some other '
                      'non-Manila Exception.'))
        self.assertRaises(exception.ManilaException, self.mediator.do_setup)

    def test_mediator_setup_client_ssh_error(self):

        # This could be anything the client comes up with, but the
        # mediator should turn it into a ManilaException.
        non_manila_exception = Exception('non-manila-except')
        self.mock_client.setSSHOptions.side_effect = non_manila_exception

        self.assertRaises(exception.ManilaException, self.mediator.do_setup)
        self.mock_client.assert_has_calls(
            [mock.call.setSSHOptions(constants.EXPECTED_IP_1234,
                                     constants.SAN_LOGIN,
                                     constants.SAN_PASSWORD,
                                     port=constants.PORT,
                                     conn_timeout=constants.TIMEOUT)])

    def test_mediator_vfs_exception(self):
        """Backend exception during get_vfs."""

        self.init_mediator()
        self.mock_client.getvfs.side_effect = Exception('non-manila-except')
        self.assertRaises(exception.ManilaException,
                          self.mediator.get_vfs,
                          fpg=constants.EXPECTED_FPG)
        expected_calls = [
            mock.call.getvfs(fpg=constants.EXPECTED_FPG, vfs=None),
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_vfs_not_found(self):
        """VFS not found."""
        self.init_mediator()
        self.mock_client.getvfs.return_value = {'total': 0}
        self.assertRaises(exception.ManilaException,
                          self.mediator.get_vfs,
                          fpg=constants.EXPECTED_FPG)
        expected_calls = [
            mock.call.getvfs(fpg=constants.EXPECTED_FPG, vfs=None),
        ]
        self.mock_client.assert_has_calls(expected_calls)

    @ddt.data((constants.EXPECTED_CLIENT_GET_VFS_RETURN_VALUE,
               constants.EXPECTED_MEDIATOR_GET_VFS_RET_VAL),
              (constants.EXPECTED_CLIENT_GET_VFS_RETURN_VALUE_MULTI,
               constants.EXPECTED_MEDIATOR_GET_VFS_RET_VAL_MULTI))
    @ddt.unpack
    def test_mediator_get_vfs(self, get_vfs_val, exp_vfs_val):
        """VFS not found."""
        self.init_mediator()
        self.mock_client.getvfs.return_value = get_vfs_val

        ret_val = self.mediator.get_vfs(constants.EXPECTED_FPG)
        self.assertEqual(exp_vfs_val, ret_val)
        expected_calls = [
            mock.call.getvfs(fpg=constants.EXPECTED_FPG, vfs=None),
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def init_mediator(self):
        """Basic mediator setup for re-use with tests that need one."""

        self.mock_client.getWsApiVersion.return_value = {
            'build': TEST_WSAPI_VERSION_STR,
        }

        self.mock_client.getvfs.return_value = {
            'total': 1,
            'members': [{'vfsname': constants.EXPECTED_VFS}]
        }
        self.mock_client.getfshare.return_value = {
            'total': 1,
            'members': [
                {'fstoreName': constants.EXPECTED_FSTORE,
                 'shareName': constants.EXPECTED_SHARE_ID,
                 'shareDir': constants.EXPECTED_SHARE_PATH,
                 'share_proto': constants.NFS,
                 'sharePath': constants.EXPECTED_SHARE_PATH,
                 'comment': constants.EXPECTED_COMMENT,
                 }]
        }
        self.mock_client.setfshare.return_value = []
        self.mock_client.setfsquota.return_value = []
        self.mock_client.getfsquota.return_value = constants.GET_FSQUOTA
        self.mediator.do_setup()

    def test_mediator_setup_success(self):
        """Do a mediator setup without errors."""

        self.init_mediator()
        self.assertIsNotNone(self.mediator._client)

        expected_calls = [
            mock.call.setSSHOptions(constants.EXPECTED_IP_1234,
                                    constants.SAN_LOGIN,
                                    constants.SAN_PASSWORD,
                                    port=constants.PORT,
                                    conn_timeout=constants.TIMEOUT),
            mock.call.getWsApiVersion(),
            mock.call.debug_rest(constants.EXPECTED_HPE_DEBUG)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_client_login_error(self):
        """Test exception during login."""
        self.init_mediator()

        self.mock_client.login.side_effect = constants.FAKE_EXCEPTION

        self.assertRaises(exception.ShareBackendException,
                          self.mediator._wsapi_login)

        expected_calls = [mock.call.login(constants.USERNAME,
                                          constants.PASSWORD)]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_client_logout_error(self):
        """Test exception during logout."""
        self.init_mediator()

        mock_log = self.mock_object(hpe3parmediator, 'LOG')
        fake_exception = constants.FAKE_EXCEPTION
        self.mock_client.http.unauthenticate.side_effect = fake_exception

        self.mediator._wsapi_logout()

        # Warning is logged (no exception thrown).
        self.assertTrue(mock_log.warning.called)
        expected_calls = [mock.call.http.unauthenticate()]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_client_version_unsupported(self):
        """Try a client with version less than minimum."""

        self.hpe3parclient = sys.modules['hpe3parclient']
        self.hpe3parclient.version_tuple = (CLIENT_VERSION_MIN_OK[0],
                                            CLIENT_VERSION_MIN_OK[1],
                                            CLIENT_VERSION_MIN_OK[2] - 1)
        mock_log = self.mock_object(hpe3parmediator, 'LOG')

        self.assertRaises(exception.HPE3ParInvalidClient,
                          self.init_mediator)

        mock_log.error.assert_called_once_with(mock.ANY)

    def test_mediator_client_version_supported(self):
        """Try a client with a version greater than the minimum."""

        # The setup success already tests the min version.  Try version > min.
        self.hpe3parclient = sys.modules['hpe3parclient']
        self.hpe3parclient.version_tuple = (CLIENT_VERSION_MIN_OK[0],
                                            CLIENT_VERSION_MIN_OK[1],
                                            CLIENT_VERSION_MIN_OK[2] + 1)
        self.init_mediator()
        expected_calls = [
            mock.call.setSSHOptions(constants.EXPECTED_IP_1234,
                                    constants.SAN_LOGIN,
                                    constants.SAN_PASSWORD,
                                    port=constants.PORT,
                                    conn_timeout=constants.TIMEOUT),
            mock.call.getWsApiVersion(),
            mock.call.debug_rest(constants.EXPECTED_HPE_DEBUG)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_client_version_exception(self):
        """Test the getWsApiVersion exception handling."""

        self.mock_client.getWsApiVersion.side_effect = constants.FAKE_EXCEPTION
        self.assertRaises(exception.ShareBackendException,
                          self.init_mediator)

    def test_mediator_client_version_bad_return_value(self):
        """Test the getWsApiVersion exception handling with bad value."""

        # Expecting a dict with 'build' in it.  This would fail badly.
        self.mock_client.getWsApiVersion.return_value = 'bogus'
        self.assertRaises(exception.ShareBackendException,
                          self.mediator.do_setup)

    def get_expected_calls_for_create_share(self,
                                            client_version,
                                            expected_fpg,
                                            expected_vfsname,
                                            expected_protocol,
                                            extra_specs,
                                            expected_project_id,
                                            expected_share_id):
        expected_sharedir = expected_share_id

        createfshare_kwargs = dict(comment=mock.ANY,
                                   fpg=expected_fpg,
                                   sharedir=expected_sharedir,
                                   fstore=expected_project_id)

        if expected_protocol == constants.NFS_LOWER:

            createfshare_kwargs['clientip'] = '127.0.0.1'

            # Options from extra-specs.
            opt_string = extra_specs.get('hpe3par:nfs_options', [])
            opt_list = opt_string.split(',')
            # Options that the mediator adds.
            nfs_options = ['rw', 'no_root_squash', 'insecure']
            nfs_options += opt_list
            expected_options = ','.join(nfs_options)

            createfshare_kwargs['options'] = OptionMatcher(
                self.assertListEqual, expected_options)

            expected_calls = [
                mock.call.createfstore(expected_vfsname, expected_project_id,
                                       comment=mock.ANY,
                                       fpg=expected_fpg),
                mock.call.getfsquota(fpg=expected_fpg,
                                     vfs=expected_vfsname,
                                     fstore=expected_project_id),
                mock.call.setfsquota(expected_vfsname,
                                     fpg=expected_fpg,
                                     hcapacity='2048',
                                     scapacity='2048',
                                     fstore=expected_project_id),
                mock.call.createfshare(expected_protocol, expected_vfsname,
                                       expected_share_id,
                                       **createfshare_kwargs),
                mock.call.getfshare(expected_protocol, expected_share_id,
                                    fpg=expected_fpg, vfs=expected_vfsname,
                                    fstore=expected_project_id)]
        else:

            smb_opts = (hpe3parmediator.ACCESS_BASED_ENUM,
                        hpe3parmediator.CONTINUOUS_AVAIL,
                        hpe3parmediator.CACHE)

            for smb_opt in smb_opts:
                opt_value = extra_specs.get('hpe3par:smb_%s' % smb_opt)
                if opt_value:
                    opt_key = hpe3parmediator.SMB_EXTRA_SPECS_MAP[smb_opt]
                    createfshare_kwargs[opt_key] = opt_value

            expected_calls = [
                mock.call.createfstore(expected_vfsname, expected_project_id,
                                       comment=mock.ANY,
                                       fpg=expected_fpg),
                mock.call.getfsquota(fpg=expected_fpg,
                                     vfs=expected_vfsname,
                                     fstore=expected_project_id),
                mock.call.setfsquota(expected_vfsname,
                                     fpg=expected_fpg,
                                     hcapacity='2048',
                                     scapacity='2048',
                                     fstore=expected_project_id),
                mock.call.createfshare(expected_protocol, expected_vfsname,
                                       expected_share_id,
                                       **createfshare_kwargs),
                mock.call.getfshare(expected_protocol, expected_share_id,
                                    fpg=expected_fpg, vfs=expected_vfsname,
                                    fstore=expected_project_id)]
        return expected_calls

    @staticmethod
    def _build_smb_extra_specs(**kwargs):
        extra_specs = {'driver_handles_share_servers': False}
        for k, v in kwargs.items():
            extra_specs['hpe3par:smb_%s' % k] = v
        return extra_specs

    @ddt.data(((4, 0, 0), None, None, None),
              ((4, 0, 0), 'true', None, None),
              ((4, 0, 0), None, 'false', None),
              ((4, 0, 0), None, 'false', None),
              ((4, 0, 0), None, None, 'optimized'),
              ((4, 0, 0), 'true', 'false', 'optimized'))
    @ddt.unpack
    def test_mediator_create_cifs_share(self, client_version, abe, ca, cache):
        self.hpe3parclient = sys.modules['hpe3parclient']
        self.hpe3parclient.version_tuple = client_version
        self.init_mediator()

        self.mock_client.getfshare.return_value = {
            'message': None,
            'total': 1,
            'members': [{'shareName': constants.EXPECTED_SHARE_NAME}]
        }

        extra_specs = self._build_smb_extra_specs(access_based_enum=abe,
                                                  continuous_avail=ca,
                                                  cache=cache)

        location = self.mediator.create_share(constants.EXPECTED_PROJECT_ID,
                                              constants.EXPECTED_SHARE_ID,
                                              constants.CIFS,
                                              extra_specs,
                                              constants.EXPECTED_FPG,
                                              constants.EXPECTED_VFS,
                                              size=constants.EXPECTED_SIZE_1)

        self.assertEqual(constants.EXPECTED_SHARE_NAME, location)

        expected_calls = self.get_expected_calls_for_create_share(
            client_version,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            constants.SMB_LOWER,
            extra_specs,
            constants.EXPECTED_PROJECT_ID,
            constants.EXPECTED_SHARE_ID)

        self.mock_client.assert_has_calls(expected_calls)

    @ddt.data('ro',
              'rw',
              'no_root_squash',
              'root_squash',
              'secure',
              'insecure',
              'hide,insecure,no_wdelay,ro,bogus,root_squash,test')
    def test_mediator_create_nfs_share_bad_options(self, nfs_options):
        self.init_mediator()

        extra_specs = {'hpe3par:nfs_options': nfs_options}

        self.assertRaises(exception.InvalidInput,
                          self.mediator.create_share,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS.lower(),
                          extra_specs,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          size=constants.EXPECTED_SIZE_1)

        self.assertFalse(self.mock_client.createfshare.called)

    @ddt.data('sync',
              'no_wdelay,sec=sys,hide,sync')
    def test_mediator_create_nfs_share(self, nfs_options):
        self.init_mediator()

        self.mock_client.getfshare.return_value = {
            'message': None,
            'total': 1,
            'members': [{'sharePath': constants.EXPECTED_SHARE_PATH}]
        }

        extra_specs = {'hpe3par:nfs_options': nfs_options}

        location = self.mediator.create_share(constants.EXPECTED_PROJECT_ID,
                                              constants.EXPECTED_SHARE_ID,
                                              constants.NFS.lower(),
                                              extra_specs,
                                              constants.EXPECTED_FPG,
                                              constants.EXPECTED_VFS,
                                              size=constants.EXPECTED_SIZE_1)

        self.assertEqual(constants.EXPECTED_SHARE_PATH, location)

        expected_calls = self.get_expected_calls_for_create_share(
            hpe3parmediator.MIN_CLIENT_VERSION,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            constants.NFS.lower(),
            extra_specs,
            constants.EXPECTED_PROJECT_ID,
            constants.EXPECTED_SHARE_ID)

        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_create_nfs_share_get_exception(self):
        self.init_mediator()

        self.mock_client.getfshare.side_effect = constants.FAKE_EXCEPTION

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_share,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS.lower(),
                          constants.EXPECTED_EXTRA_SPECS,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          size=constants.EXPECTED_SIZE_1)

    @ddt.data(0, 2)
    def test_mediator_create_nfs_share_get_fail(self, count):
        self.init_mediator()

        self.mock_client.getfshare.return_value = {'total': count}

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_share,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS.lower(),
                          constants.EXPECTED_EXTRA_SPECS,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          size=constants.EXPECTED_SIZE_1)

    @ddt.data(True, False)
    def test_mediator_create_cifs_share_from_snapshot(self, require_cifs_ip):
        self.init_mediator()
        self.mediator.hpe3par_require_cifs_ip = require_cifs_ip

        self.mock_client.getfsnap.return_value = {
            'message': None,
            'total': 1,
            'members': [{'snapName': constants.EXPECTED_SNAP_ID,
                         'fstoreName': constants.EXPECTED_FSTORE}]
        }

        location = self.mediator.create_share_from_snapshot(
            constants.EXPECTED_SHARE_ID,
            constants.CIFS,
            constants.EXPECTED_EXTRA_SPECS,
            constants.EXPECTED_PROJECT_ID,
            constants.EXPECTED_SHARE_ID,
            constants.EXPECTED_SNAP_ID,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            [constants.EXPECTED_IP_10203040])

        self.assertEqual(constants.EXPECTED_SHARE_ID, location)

        expected_kwargs_ro = {
            'comment': mock.ANY,
            'fpg': constants.EXPECTED_FPG,
            'fstore': constants.EXPECTED_FSTORE,
        }
        expected_kwargs_rw = expected_kwargs_ro.copy()

        expected_kwargs_ro['sharedir'] = '.snapshot/%s/%s' % (
            constants.EXPECTED_SNAP_ID, constants.EXPECTED_SHARE_ID)
        expected_kwargs_rw['sharedir'] = constants.EXPECTED_SHARE_ID

        if require_cifs_ip:
            expected_kwargs_ro['allowip'] = constants.EXPECTED_MY_IP
            expected_kwargs_rw['allowip'] = (
                ','.join((constants.EXPECTED_MY_IP,
                          constants.EXPECTED_IP_127)))

        expected_calls = [
            mock.call.getfsnap('*_%s' % constants.EXPECTED_SNAP_ID,
                               vfs=constants.EXPECTED_VFS,
                               fpg=constants.EXPECTED_FPG,
                               pat=True,
                               fstore=constants.EXPECTED_FSTORE),
            mock.call.createfshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   **expected_kwargs_ro),
            mock.call.getfshare(constants.SMB_LOWER,
                                constants.EXPECTED_SHARE_ID,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.createfshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   **expected_kwargs_rw),
            mock.call.getfshare(constants.SMB_LOWER,
                                constants.EXPECTED_SHARE_ID,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                allowperm=constants.ADD_USERNAME,
                                comment=mock.ANY,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                allowperm=constants.ADD_USERNAME,
                                comment=mock.ANY,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SUPER_SHARE,
                                allowperm=constants.DROP_USERNAME,
                                comment=mock.ANY,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.removefshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_FSTORE),
        ]

        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_create_cifs_share_from_snapshot_ro(self):
        self.init_mediator()

        # RO because CIFS admin access username is not configured
        self.mediator.hpe3par_cifs_admin_access_username = None

        self.mock_client.getfsnap.return_value = {
            'message': None,
            'total': 1,
            'members': [{'snapName': constants.EXPECTED_SNAP_ID,
                         'fstoreName': constants.EXPECTED_FSTORE}]
        }

        location = self.mediator.create_share_from_snapshot(
            constants.EXPECTED_SHARE_ID,
            constants.CIFS,
            constants.EXPECTED_EXTRA_SPECS,
            constants.EXPECTED_PROJECT_ID,
            constants.EXPECTED_SHARE_ID,
            constants.EXPECTED_SNAP_ID,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            [constants.EXPECTED_IP_10203040],
            comment=constants.EXPECTED_COMMENT)

        self.assertEqual(constants.EXPECTED_SHARE_ID, location)

        share_dir = '.snapshot/%s/%s' % (
            constants.EXPECTED_SNAP_ID, constants.EXPECTED_SHARE_ID)

        expected_kwargs_ro = {
            'comment': constants.EXPECTED_COMMENT,
            'fpg': constants.EXPECTED_FPG,
            'fstore': constants.EXPECTED_FSTORE,
            'sharedir': share_dir,
        }

        self.mock_client.createfshare.assert_called_once_with(
            constants.SMB_LOWER,
            constants.EXPECTED_VFS,
            constants.EXPECTED_SHARE_ID,
            **expected_kwargs_ro
        )

    def test_mediator_create_nfs_share_from_snapshot(self):
        self.init_mediator()

        self.mock_client.getfsnap.return_value = {
            'message': None,
            'total': 1,
            'members': [{'snapName': constants.EXPECTED_SNAP_ID,
                         'fstoreName': constants.EXPECTED_FSTORE}]
        }

        location = self.mediator.create_share_from_snapshot(
            constants.EXPECTED_SHARE_ID,
            constants.NFS,
            constants.EXPECTED_EXTRA_SPECS,
            constants.EXPECTED_PROJECT_ID,
            constants.EXPECTED_SHARE_ID,
            constants.EXPECTED_SNAP_ID,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            [constants.EXPECTED_IP_10203040])

        self.assertEqual(constants.EXPECTED_SHARE_PATH, location)

        expected_calls = [
            mock.call.getfsnap('*_%s' % constants.EXPECTED_SNAP_ID,
                               vfs=constants.EXPECTED_VFS,
                               fpg=constants.EXPECTED_FPG,
                               pat=True,
                               fstore=constants.EXPECTED_FSTORE),
            mock.call.createfshare(constants.NFS_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   comment=mock.ANY,
                                   fpg=constants.EXPECTED_FPG,
                                   sharedir='.snapshot/%s/%s' %
                                            (constants.EXPECTED_SNAP_ID,
                                             constants.EXPECTED_SHARE_ID),
                                   fstore=constants.EXPECTED_FSTORE,
                                   clientip=constants.EXPECTED_MY_IP,
                                   options='ro,no_root_squash,insecure'),
            mock.call.getfshare(constants.NFS_LOWER,
                                constants.EXPECTED_SHARE_ID,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.createfshare(constants.NFS_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   comment=mock.ANY,
                                   fpg=constants.EXPECTED_FPG,
                                   sharedir=constants.EXPECTED_SHARE_ID,
                                   fstore=constants.EXPECTED_FSTORE,
                                   clientip=','.join((
                                       constants.EXPECTED_MY_IP,
                                       constants.EXPECTED_IP_127)),
                                   options='rw,no_root_squash,insecure'),
            mock.call.getfshare(constants.NFS_LOWER,
                                constants.EXPECTED_SHARE_ID,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.getfshare(constants.NFS_LOWER,
                                constants.EXPECTED_SHARE_ID,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.setfshare(constants.NFS_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                clientip=''.join(('-',
                                                 constants.EXPECTED_MY_IP)),
                                comment=mock.ANY,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.removefshare(constants.NFS_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_FSTORE),
        ]

        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_create_share_from_snap_copy_incomplete(self):
        self.init_mediator()

        self.mock_client.getfsnap.return_value = {
            'message': None,
            'total': 1,
            'members': [{'snapName': constants.EXPECTED_SNAP_ID,
                         'fstoreName': constants.EXPECTED_FSTORE}]
        }

        mock_bad_copy = mock.Mock()
        mock_bad_copy.get_progress.return_value = {'total_progress': 99}
        self.mock_object(
            data_utils, 'Copy', mock.Mock(return_value=mock_bad_copy))

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_share_from_snapshot,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_EXTRA_SPECS,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.EXPECTED_SNAP_ID,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          [constants.EXPECTED_IP_10203040])
        self.assertTrue(mock_bad_copy.run.called)
        self.assertTrue(mock_bad_copy.get_progress.called)

    def test_mediator_create_share_from_snap_copy_exception(self):
        self.init_mediator()

        self.mock_client.getfsnap.return_value = {
            'message': None,
            'total': 1,
            'members': [{'snapName': constants.EXPECTED_SNAP_ID,
                         'fstoreName': constants.EXPECTED_FSTORE}]
        }

        mock_bad_copy = mock.Mock()
        mock_bad_copy.run.side_effect = Exception('run exception')
        self.mock_object(
            data_utils, 'Copy', mock.Mock(return_value=mock_bad_copy))

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_share_from_snapshot,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_EXTRA_SPECS,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.EXPECTED_SNAP_ID,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          [constants.EXPECTED_IP_10203040])
        self.assertTrue(mock_bad_copy.run.called)

    def test_mediator_create_share_from_snap_not_found(self):
        self.init_mediator()

        self.mock_client.getfsnap.return_value = {
            'message': None,
            'total': 0,
            'members': []
        }

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_share_from_snapshot,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_EXTRA_SPECS,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.EXPECTED_SNAP_ID,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          [constants.EXPECTED_IP_10203040])

    def test_mediator_delete_nfs_share(self):
        self.init_mediator()

        share_id = 'foo'
        osf_share_id = '-'.join(('osf', share_id))
        osf_ro_share_id = '-ro-'.join(('osf', share_id))
        fstore = osf_share_id

        self.mock_object(self.mediator,
                         '_find_fstore',
                         mock.Mock(return_value=fstore))
        self.mock_object(self.mediator, '_delete_file_tree')
        self.mock_object(self.mediator, '_update_capacity_quotas')

        self.mediator.delete_share(constants.EXPECTED_PROJECT_ID,
                                   share_id,
                                   constants.EXPECTED_SIZE_1,
                                   constants.NFS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_IP)

        expected_calls = [
            mock.call.removefshare(constants.NFS_LOWER,
                                   constants.EXPECTED_VFS,
                                   osf_share_id,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=fstore),
            mock.call.removefshare(constants.NFS_LOWER,
                                   constants.EXPECTED_VFS,
                                   osf_ro_share_id,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=fstore),
            mock.call.removefstore(constants.EXPECTED_VFS,
                                   fstore,
                                   fpg=constants.EXPECTED_FPG),
        ]
        self.mock_client.assert_has_calls(expected_calls)

        self.assertFalse(self.mediator._delete_file_tree.called)
        self.assertFalse(self.mediator._update_capacity_quotas.called)

    def test_mediator_delete_share_not_found(self):
        self.init_mediator()

        self.mock_object(self.mediator,
                         '_find_fstore',
                         mock.Mock(return_value=None))
        self.mock_object(self.mediator, '_delete_file_tree')
        self.mock_object(self.mediator, '_update_capacity_quotas')

        self.mediator.delete_share(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.EXPECTED_SIZE_1,
                                   constants.CIFS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_IP_10203040)

        self.assertFalse(self.mock_client.removefshare.called)

        self.assertFalse(self.mediator._delete_file_tree.called)
        self.assertFalse(self.mediator._update_capacity_quotas.called)

    def test_mediator_delete_nfs_share_only_readonly(self):
        self.init_mediator()

        fstores = (None, constants.EXPECTED_FSTORE)
        self.mock_object(self.mediator,
                         '_find_fstore',
                         mock.Mock(side_effect=fstores))
        self.mock_object(self.mediator, '_delete_file_tree')
        self.mock_object(self.mediator, '_update_capacity_quotas')

        self.mediator.delete_share(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.EXPECTED_SIZE_1,
                                   constants.NFS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_IP_10203040)

        self.mock_client.removefshare.assert_called_once_with(
            constants.NFS_LOWER,
            constants.EXPECTED_VFS,
            constants.EXPECTED_SHARE_ID,
            fpg=constants.EXPECTED_FPG,
            fstore=constants.EXPECTED_FSTORE
        )

        self.assertFalse(self.mediator._delete_file_tree.called)
        self.assertFalse(self.mediator._update_capacity_quotas.called)

    def test_mediator_delete_share_exception(self):
        self.init_mediator()
        self.mock_client.removefshare.side_effect = Exception(
            'removeshare fail.')

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.delete_share,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.EXPECTED_SIZE_1,
                          constants.CIFS,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          constants.EXPECTED_IP_10203040)

        expected_calls = [
            mock.call.removefshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_FSTORE),
        ]

        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_delete_fstore_exception(self):
        self.init_mediator()
        self.mock_object(self.mediator,
                         '_find_fstore',
                         mock.Mock(return_value=constants.EXPECTED_SHARE_ID))
        self.mock_object(self.mediator, '_delete_file_tree')
        self.mock_object(self.mediator, '_update_capacity_quotas')
        self.mock_client.removefstore.side_effect = Exception(
            'removefstore fail.')

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.delete_share,
                          constants.EXPECTED_PROJECT_ID,
                          constants.SHARE_ID,
                          constants.EXPECTED_SIZE_1,
                          constants.CIFS,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          constants.EXPECTED_IP_10203040)

        expected_calls = [
            mock.call.removefshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_SHARE_ID),
            mock.call.removefshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID_RO,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_SHARE_ID),
            mock.call.removefstore(constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   fpg=constants.EXPECTED_FPG),
        ]
        self.mock_client.assert_has_calls(expected_calls)

        self.assertFalse(self.mediator._delete_file_tree.called)
        self.assertFalse(self.mediator._update_capacity_quotas.called)

    def test_mediator_delete_file_tree_exception(self):
        self.init_mediator()
        mock_log = self.mock_object(hpe3parmediator, 'LOG')
        self.mock_object(self.mediator,
                         '_find_fstore',
                         mock.Mock(return_value=constants.EXPECTED_FSTORE))
        self.mock_object(self.mediator,
                         '_delete_file_tree',
                         mock.Mock(side_effect=Exception('test')))
        self.mock_object(self.mediator, '_update_capacity_quotas')

        self.mediator.delete_share(constants.EXPECTED_PROJECT_ID,
                                   constants.SHARE_ID,
                                   constants.EXPECTED_SIZE_1,
                                   constants.CIFS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_IP_10203040)

        expected_calls = [
            mock.call.removefshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_FSTORE),
            mock.call.removefshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID_RO,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_FSTORE),
        ]
        self.mock_client.assert_has_calls(expected_calls)

        self.assertTrue(self.mediator._delete_file_tree.called)
        self.assertFalse(self.mediator._update_capacity_quotas.called)
        mock_log.warning.assert_called_once_with(mock.ANY, mock.ANY)

    def test_mediator_delete_cifs_share(self):
        self.init_mediator()

        self.mock_object(self.mediator,
                         '_find_fstore',
                         mock.Mock(return_value=constants.EXPECTED_FSTORE))
        self.mock_object(self.mediator,
                         '_create_mount_directory',
                         mock.Mock(return_value={}))
        self.mock_object(self.mediator,
                         '_mount_super_share',
                         mock.Mock(return_value={}))
        self.mock_object(self.mediator,
                         '_delete_share_directory',
                         mock.Mock(return_value={}))
        self.mock_object(self.mediator,
                         '_unmount_share',
                         mock.Mock(return_value={}))
        self.mock_object(self.mediator,
                         '_update_capacity_quotas',
                         mock.Mock(return_value={}))

        self.mediator.delete_share(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.EXPECTED_SIZE_1,
                                   constants.CIFS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_IP_10203040)

        expected_calls = [
            mock.call.removefshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_FSTORE),
            mock.call.createfshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SUPER_SHARE,
                                   allowip=constants.EXPECTED_MY_IP,
                                   comment=(
                                       constants.EXPECTED_SUPER_SHARE_COMMENT),
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_FSTORE,
                                   sharedir=''),
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SUPER_SHARE,
                                comment=(
                                    constants.EXPECTED_SUPER_SHARE_COMMENT),
                                allowperm=(
                                    '+' + constants.USERNAME + ':fullcontrol'),
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE),
        ]
        self.mock_client.assert_has_calls(expected_calls)

        expected_mount_path = constants.EXPECTED_MOUNT_PATH + (
            constants.EXPECTED_SHARE_ID)

        expected_share_path = '/'.join((expected_mount_path,
                                        constants.EXPECTED_SHARE_ID))
        self.mediator._create_mount_directory.assert_called_once_with(
            expected_mount_path)
        self.mediator._mount_super_share.assert_called_once_with(
            constants.SMB_LOWER,
            expected_mount_path,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            constants.EXPECTED_FSTORE,
            constants.EXPECTED_IP_10203040)
        self.mediator._delete_share_directory.assert_has_calls([
            mock.call(expected_share_path),
            mock.call(expected_mount_path),
        ])
        self.mediator._unmount_share.assert_called_once_with(
            expected_mount_path)
        self.mediator._update_capacity_quotas.assert_called_once_with(
            constants.EXPECTED_FSTORE,
            0,
            constants.EXPECTED_SIZE_1,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS)

    def test_mediator_delete_cifs_share_and_fstore(self):
        self.init_mediator()

        self.mock_object(self.mediator,
                         '_find_fstore',
                         mock.Mock(return_value=constants.EXPECTED_SHARE_ID))
        self.mock_object(self.mediator, '_delete_file_tree')
        self.mock_object(self.mediator, '_update_capacity_quotas')

        self.mediator.delete_share(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.EXPECTED_SIZE_1,
                                   constants.CIFS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_IP_10203040)

        expected_calls = [
            mock.call.removefshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_SHARE_ID),
            mock.call.removefstore(constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   fpg=constants.EXPECTED_FPG),
        ]
        self.mock_client.assert_has_calls(expected_calls)

        self.assertFalse(self.mediator._delete_file_tree.called)
        self.assertFalse(self.mediator._update_capacity_quotas.called)

    def test_mediator_delete_share_with_fstore_per_share_false(self):
        self.init_mediator()
        self.mediator.hpe3par_fstore_per_share = False
        share_size = int(constants.EXPECTED_SIZE_1)
        fstore_init_size = int(
            constants.GET_FSQUOTA['members'][0]['hardBlock'])

        expected_capacity = (0-share_size) * units.Ki + fstore_init_size
        self.mock_object(self.mediator,
                         '_find_fstore',
                         mock.Mock(return_value=constants.EXPECTED_FSTORE))
        self.mock_object(self.mediator,
                         '_create_mount_directory',
                         mock.Mock(return_value={}))
        self.mock_object(self.mediator,
                         '_mount_super_share',
                         mock.Mock(return_value={}))
        self.mock_object(self.mediator,
                         '_delete_share_directory',
                         mock.Mock(return_value={}))
        self.mock_object(self.mediator,
                         '_unmount_share',
                         mock.Mock(return_value={}))

        self.mediator.delete_share(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.EXPECTED_SIZE_1,
                                   constants.CIFS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_IP_10203040)

        expected_calls = [
            mock.call.removefshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_FSTORE),
            mock.call.createfshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SUPER_SHARE,
                                   allowip=constants.EXPECTED_MY_IP,
                                   comment=(
                                       constants.EXPECTED_SUPER_SHARE_COMMENT),
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=constants.EXPECTED_FSTORE,
                                   sharedir=''),
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SUPER_SHARE,
                                comment=(
                                    constants.EXPECTED_SUPER_SHARE_COMMENT),
                                allowperm=(
                                    '+' + constants.USERNAME + ':fullcontrol'),
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.getfsquota(fpg=constants.EXPECTED_FPG,
                                 fstore=constants.EXPECTED_FSTORE,
                                 vfs=constants.EXPECTED_VFS),
            mock.call.setfsquota(constants.EXPECTED_VFS,
                                 fpg=constants.EXPECTED_FPG,
                                 fstore=constants.EXPECTED_FSTORE,
                                 scapacity=six.text_type(expected_capacity),
                                 hcapacity=six.text_type(expected_capacity))]
        self.mock_client.assert_has_calls(expected_calls)

        expected_mount_path = constants.EXPECTED_MOUNT_PATH + (
            constants.EXPECTED_SHARE_ID)
        self.mediator._create_mount_directory.assert_called_with(
            expected_mount_path)
        self.mediator._mount_super_share.assert_called_with(
            constants.SMB_LOWER, expected_mount_path, constants.EXPECTED_FPG,
            constants.EXPECTED_VFS, constants.EXPECTED_FSTORE,
            constants.EXPECTED_IP_10203040)
        self.mediator._delete_share_directory.assert_called_with(
            expected_mount_path)
        self.mediator._unmount_share.assert_called_with(
            expected_mount_path)

    def test_mediator_create_snapshot(self):
        self.init_mediator()

        self.mediator.create_snapshot(constants.EXPECTED_PROJECT_ID,
                                      constants.EXPECTED_SHARE_ID,
                                      constants.NFS,
                                      constants.EXPECTED_SNAP_NAME,
                                      constants.EXPECTED_FPG,
                                      constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.createfsnap(constants.EXPECTED_VFS,
                                  constants.EXPECTED_PROJECT_ID,
                                  constants.EXPECTED_SNAP_NAME,
                                  fpg=constants.EXPECTED_FPG)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_create_snapshot_not_allowed(self):
        self.init_mediator()
        self.mock_client.getfshare.return_value['members'][0]['shareDir'] = (
            None)
        self.mock_client.getfshare.return_value['members'][0]['sharePath'] = (
            'foo/.snapshot/foo')

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_snapshot,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_SNAP_NAME,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def test_mediator_create_snapshot_share_not_found(self):
        self.init_mediator()

        mock_find_fshare = self.mock_object(self.mediator,
                                            '_find_fshare',
                                            mock.Mock(return_value=None))

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_snapshot,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_SNAP_NAME,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

        mock_find_fshare.assert_called_once_with(constants.EXPECTED_PROJECT_ID,
                                                 constants.EXPECTED_SHARE_ID,
                                                 constants.NFS,
                                                 constants.EXPECTED_FPG,
                                                 constants.EXPECTED_VFS)

    def test_mediator_create_snapshot_backend_exception(self):
        self.init_mediator()

        # createfsnap exception
        self.mock_client.createfsnap.side_effect = Exception(
            'createfsnap fail.')

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_snapshot,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_SNAP_NAME,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def test_mediator_delete_snapshot(self):
        self.init_mediator()

        expected_name_from_array = 'name-from-array'

        self.mock_client.getfsnap.return_value = {
            'total': 1,
            'members': [
                {
                    'snapName': expected_name_from_array,
                    'fstoreName': constants.EXPECTED_PROJECT_ID,
                }
            ],
            'message': None
        }

        self.mock_client.getfshare.side_effect = [
            # some typical independent NFS share (path) and SMB share (dir)
            {
                'total': 1,
                'members': [{'sharePath': '/anyfpg/anyvfs/anyfstore'}]
            },
            {
                'total': 1,
                'members': [{'shareDir': []}],
            }
        ]

        self.mediator.delete_snapshot(constants.EXPECTED_PROJECT_ID,
                                      constants.EXPECTED_SHARE_ID,
                                      constants.NFS,
                                      constants.EXPECTED_SNAP_NAME,
                                      constants.EXPECTED_FPG,
                                      constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.getfsnap('*_%s' % constants.EXPECTED_SNAP_NAME,
                               vfs=constants.EXPECTED_VFS,
                               fpg=constants.EXPECTED_FPG,
                               pat=True,
                               fstore=constants.EXPECTED_PROJECT_ID),
            mock.call.getfshare(constants.NFS_LOWER,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_PROJECT_ID),
            mock.call.getfshare(constants.SMB_LOWER,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_PROJECT_ID),
            mock.call.removefsnap(constants.EXPECTED_VFS,
                                  constants.EXPECTED_PROJECT_ID,
                                  fpg=constants.EXPECTED_FPG,
                                  snapname=expected_name_from_array),
            mock.call.startfsnapclean(constants.EXPECTED_FPG,
                                      reclaimStrategy='maxspeed')
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_delete_snapshot_not_found(self):
        self.init_mediator()

        self.mock_client.getfsnap.return_value = {
            'total': 0,
            'members': [],
        }

        self.mediator.delete_snapshot(constants.EXPECTED_PROJECT_ID,
                                      constants.EXPECTED_SHARE_ID,
                                      constants.NFS,
                                      constants.EXPECTED_SNAP_NAME,
                                      constants.EXPECTED_FPG,
                                      constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.getfsnap('*_%s' % constants.EXPECTED_SNAP_NAME,
                               vfs=constants.EXPECTED_VFS,
                               fpg=constants.EXPECTED_FPG,
                               pat=True,
                               fstore=constants.EXPECTED_SHARE_ID),
        ]

        # Code coverage for early exit when nothing to delete.
        self.mock_client.assert_has_calls(expected_calls)
        self.assertFalse(self.mock_client.getfshare.called)
        self.assertFalse(self.mock_client.removefsnap.called)
        self.assertFalse(self.mock_client.startfsnapclean.called)

    def test_mediator_delete_snapshot_shared_nfs(self):
        self.init_mediator()

        # Mock a share under this snapshot for NFS
        snapshot_dir = '.snapshot/DT_%s' % constants.EXPECTED_SNAP_NAME
        snapshot_path = '%s/%s' % (constants.EXPECTED_SHARE_PATH, snapshot_dir)

        self.mock_client.getfsnap.return_value = {
            'total': 1,
            'members': [{'snapName': constants.EXPECTED_SNAP_NAME}]
        }

        self.mock_client.getfshare.side_effect = [
            # some typical independent NFS share (path) and SMB share (dir)
            {
                'total': 1,
                'members': [{'sharePath': snapshot_path}],
            },
            {
                'total': 0,
                'members': [],
            }
        ]

        self.assertRaises(exception.Invalid,
                          self.mediator.delete_snapshot,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_SNAP_NAME,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def test_mediator_delete_snapshot_shared_smb(self):
        self.init_mediator()

        # Mock a share under this snapshot for SMB
        snapshot_dir = '.snapshot/DT_%s' % constants.EXPECTED_SNAP_NAME

        self.mock_client.getfsnap.return_value = {
            'total': 1,
            'members': [{'snapName': constants.EXPECTED_SNAP_NAME}]
        }

        self.mock_client.getfshare.side_effect = [
            # some typical independent NFS share (path) and SMB share (dir)
            {
                'total': 1,
                'members': [{'sharePath': constants.EXPECTED_SHARE_PATH}],
            },
            {
                'total': 1,
                'members': [{'shareDir': snapshot_dir}],
            }
        ]

        self.assertRaises(exception.Invalid,
                          self.mediator.delete_snapshot,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_SNAP_NAME,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def _assert_delete_snapshot_raises(self):
        self.assertRaises(exception.ShareBackendException,
                          self.mediator.delete_snapshot,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_SNAP_NAME,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def test_mediator_delete_snapshot_backend_exceptions(self):
        self.init_mediator()

        # getfsnap exception
        self.mock_client.getfsnap.side_effect = Exception('getfsnap fail.')
        self._assert_delete_snapshot_raises()

        # getfsnap OK
        self.mock_client.getfsnap.side_effect = None
        self.mock_client.getfsnap.return_value = {
            'total': 1,
            'members': [{'snapName': constants.EXPECTED_SNAP_NAME,
                         'fstoreName': constants.EXPECTED_FSTORE}]
        }

        # getfshare exception
        self.mock_client.getfshare.side_effect = Exception('getfshare fail.')
        self._assert_delete_snapshot_raises()

        # getfshare OK
        def mock_fshare(*args, **kwargs):
            if args[0] == constants.NFS_LOWER:
                return {
                    'total': 1,
                    'members': [{'sharePath': '/anyfpg/anyvfs/anyfstore',
                                 'fstoreName': constants.EXPECTED_FSTORE}]
                }
            else:
                return {
                    'total': 1,
                    'members': [{'shareDir': [],
                                 'fstoreName': constants.EXPECTED_FSTORE}]
                }

        self.mock_client.getfshare.side_effect = mock_fshare

        # removefsnap exception
        self.mock_client.removefsnap.side_effect = Exception(
            'removefsnap fail.')
        self._assert_delete_snapshot_raises()

        # removefsnap OK
        self.mock_client.removefsnap.side_effect = None
        self.mock_client.removefsnap.return_value = []

        # startfsnapclean exception (logged, not raised)
        self.mock_client.startfsnapclean.side_effect = Exception(
            'startfsnapclean fail.')
        mock_log = self.mock_object(hpe3parmediator, 'LOG')

        self.mediator.delete_snapshot(constants.EXPECTED_PROJECT_ID,
                                      constants.EXPECTED_SHARE_ID,
                                      constants.NFS,
                                      constants.EXPECTED_SNAP_NAME,
                                      constants.EXPECTED_FPG,
                                      constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.getfsnap('*_%s' % constants.EXPECTED_SNAP_NAME,
                               vfs=constants.EXPECTED_VFS,
                               fpg=constants.EXPECTED_FPG,
                               pat=True,
                               fstore=constants.EXPECTED_FSTORE),
            mock.call.getfshare(constants.NFS_LOWER,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.getfshare(constants.SMB_LOWER,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_FSTORE),
            mock.call.removefsnap(constants.EXPECTED_VFS,
                                  constants.EXPECTED_FSTORE,
                                  fpg=constants.EXPECTED_FPG,
                                  snapname=constants.EXPECTED_SNAP_NAME),
            mock.call.startfsnapclean(constants.EXPECTED_FPG,
                                      reclaimStrategy='maxspeed'),
        ]
        self.mock_client.assert_has_calls(expected_calls)
        self.assertTrue(mock_log.debug.called)
        self.assertTrue(mock_log.exception.called)

    @ddt.data(six.text_type('volname.1'), ['volname.2', 'volname.3'])
    def test_mediator_get_fpg_status(self, volume_name_or_list):
        """Mediator converts client stats to capacity result."""
        expected_capacity = constants.EXPECTED_SIZE_2
        expected_free = constants.EXPECTED_SIZE_1

        self.init_mediator()
        self.mock_client.getfpg.return_value = {
            'total': 1,
            'members': [
                {
                    'capacityKiB': str(expected_capacity * units.Mi),
                    'availCapacityKiB': str(expected_free * units.Mi),
                    'vvs': volume_name_or_list,
                }
            ],
            'message': None,
        }

        self.mock_client.getfsquota.return_value = {
            'total': 3,
            'members': [
                {'hardBlock': 1 * units.Ki},
                {'hardBlock': 2 * units.Ki},
                {'hardBlock': 3 * units.Ki},
            ],
            'message': None,
        }

        self.mock_client.getVolume.return_value = {
            'provisioningType': hpe3parmediator.DEDUPE}

        expected_result = {
            'pool_name': constants.EXPECTED_FPG,
            'free_capacity_gb': expected_free,
            'hpe3par_flash_cache': False,
            'hp3par_flash_cache': False,
            'dedupe': True,
            'thin_provisioning': True,
            'total_capacity_gb': expected_capacity,
            'provisioned_capacity_gb': 6,
        }

        result = self.mediator.get_fpg_status(constants.EXPECTED_FPG)
        self.assertEqual(expected_result, result)
        expected_calls = [
            mock.call.getfpg(constants.EXPECTED_FPG)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_get_fpg_status_exception(self):
        """Exception during get_fpg_status call to getfpg."""
        self.init_mediator()

        self.mock_client.getfpg.side_effect = constants.FAKE_EXCEPTION

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.get_fpg_status,
                          constants.EXPECTED_FPG)

        expected_calls = [mock.call.getfpg(constants.EXPECTED_FPG)]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_get_fpg_status_error(self):
        """Unexpected result from getfpg during get_fpg_status."""
        self.init_mediator()

        self.mock_client.getfpg.return_value = {'total': 0}

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.get_fpg_status,
                          constants.EXPECTED_FPG)

        expected_calls = [mock.call.getfpg(constants.EXPECTED_FPG)]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_get_fpg_status_bad_prov_type(self):
        """Test get_fpg_status handling of unexpected provisioning type."""
        self.init_mediator()

        self.mock_client.getfpg.return_value = {
            'total': 1,
            'members': [
                {
                    'capacityKiB': '1',
                    'availCapacityKiB': '1',
                    'vvs': 'foo',
                }
            ],
            'message': None,
        }
        self.mock_client.getVolume.return_value = {
            'provisioningType': 'BOGUS'}

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.get_fpg_status,
                          constants.EXPECTED_FPG)

        expected_calls = [mock.call.getfpg(constants.EXPECTED_FPG)]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_get_provisioned_error(self):
        """Test error during get provisioned GB."""
        self.init_mediator()

        error_return = {'message': 'Some error happened.'}
        self.mock_client.getfsquota.return_value = error_return

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.get_provisioned_gb,
                          constants.EXPECTED_FPG)

        expected_calls = [mock.call.getfsquota(fpg=constants.EXPECTED_FPG)]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_get_provisioned_exception(self):
        """Test exception during get provisioned GB."""
        self.init_mediator()

        self.mock_client.getfsquota.side_effect = constants.FAKE_EXCEPTION

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.get_provisioned_gb,
                          constants.EXPECTED_FPG)

        expected_calls = [mock.call.getfsquota(fpg=constants.EXPECTED_FPG)]
        self.mock_client.assert_has_calls(expected_calls)

    def test_update_access_resync_rules_nfs(self):
        self.init_mediator()

        getfshare_result = {
            'shareName': constants.EXPECTED_SHARE_NAME,
            'fstoreName': constants.EXPECTED_FSTORE,
            'clients': [constants.EXPECTED_IP_127],
            'comment': constants.EXPECTED_COMMENT,
        }
        self.mock_client.getfshare.return_value = {
            'total': 1,
            'members': [getfshare_result],
            'message': None,
        }

        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.NFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_NFS],
                                    None,
                                    None,
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(
                constants.NFS_LOWER,
                constants.EXPECTED_VFS,
                constants.EXPECTED_SHARE_NAME,
                clientip='+'+constants.EXPECTED_IP_1234,
                fpg=constants.EXPECTED_FPG,
                fstore=constants.EXPECTED_FSTORE,
                comment=constants.EXPECTED_COMMENT),
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_update_access_resync_rules_cifs(self):
        self.init_mediator()

        getfshare_result = {
            'shareName': constants.EXPECTED_SHARE_NAME,
            'fstoreName': constants.EXPECTED_FSTORE,
            'allowPerm': [['foo_user', 'fullcontrol']],
            'allowIP': '',
            'comment': constants.EXPECTED_COMMENT,
        }
        self.mock_client.getfshare.return_value = {
            'total': 1,
            'members': [getfshare_result],
            'message': None,
        }

        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.CIFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_CIFS],
                                    None,
                                    None,
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(
                constants.SMB_LOWER,
                constants.EXPECTED_VFS,
                constants.EXPECTED_SHARE_NAME,
                allowperm='+' + constants.USERNAME + ':fullcontrol',
                fpg=constants.EXPECTED_FPG,
                fstore=constants.EXPECTED_FSTORE,
                comment=constants.EXPECTED_COMMENT),
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_allow_ip_ro_access_cifs_error(self):
        self.init_mediator()

        self.assertRaises(exception.InvalidShareAccess,
                          self.mediator.update_access,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.CIFS,
                          constants.EXPECTED_EXTRA_SPECS,
                          [constants.ACCESS_RULE_NFS],
                          [constants.ADD_RULE_IP_RO],
                          [],
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    @ddt.data(constants.CIFS, constants.NFS)
    def test_mediator_allow_rw_snapshot_error(self, proto):
        self.init_mediator()
        getfshare_result = {
            'shareName': 'foo_ro_name',
            'fstoreName': 'foo_fstore',
            'comment': 'foo_comment',
        }
        path = 'foo/.snapshot/foo'
        if proto == constants.NFS:
            getfshare_result['sharePath'] = path
        else:
            getfshare_result['shareDir'] = path

        self.mock_client.getfshare.return_value = {
            'total': 1,
            'members': [getfshare_result],
            'message': None,
        }

        self.assertRaises(exception.InvalidShareAccess,
                          self.mediator.update_access,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.CIFS,
                          constants.EXPECTED_EXTRA_SPECS,
                          [constants.ACCESS_RULE_NFS],
                          [constants.ADD_RULE_IP],
                          [],
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    @ddt.data((constants.READ_WRITE, True),
              (constants.READ_WRITE, False),
              (constants.READ_ONLY, True),
              (constants.READ_ONLY, False))
    @ddt.unpack
    def test_mediator_allow_user_access_cifs(self, access_level, use_other):
        """"Allow user access to cifs share."""
        self.init_mediator()

        if use_other:  # Don't find share until second attempt.
            findings = (None,
                        self.mock_client.getfshare.return_value['members'][0])
            mock_find_fshare = self.mock_object(
                self.mediator, '_find_fshare', mock.Mock(side_effect=findings))

        if access_level == constants.READ_ONLY:
            expected_allowperm = '+%s:read' % constants.USERNAME
        else:
            expected_allowperm = '+%s:fullcontrol' % constants.USERNAME

        constants.ADD_RULE_USER['access_level'] = access_level
        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.CIFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_CIFS],
                                    [constants.ADD_RULE_USER],
                                    [],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                allowperm=expected_allowperm,
                                comment=constants.EXPECTED_COMMENT,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE)

        ]
        self.mock_client.assert_has_calls(expected_calls)
        if use_other:
            readonly = access_level == constants.READ_ONLY
            expected_find_calls = [
                mock.call(constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.SMB_LOWER,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          readonly=readonly),
                mock.call(constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.SMB_LOWER,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          readonly=not readonly),
            ]
            mock_find_fshare.assert_has_calls(expected_find_calls)

    @ddt.data(constants.CIFS, constants.NFS)
    def test_mediator_deny_rw_snapshot_error(self, proto):
        self.init_mediator()
        getfshare_result = {
            'shareName': 'foo_ro_name',
            'fstoreName': 'foo_fstore',
            'comment': 'foo_comment',
        }
        path = 'foo/.snapshot/foo'
        if proto == constants.NFS:
            getfshare_result['sharePath'] = path
        else:
            getfshare_result['shareDir'] = path

        self.mock_client.getfshare.return_value = {
            'total': 1,
            'members': [getfshare_result],
            'message': None,
        }
        mock_log = self.mock_object(hpe3parmediator, 'LOG')

        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    proto,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_NFS],
                                    [],
                                    [constants.DELETE_RULE_IP],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        self.assertFalse(self.mock_client.setfshare.called)
        self.assertTrue(mock_log.error.called)

    def test_mediator_deny_user_access_cifs(self):
        """"Deny user access to cifs share."""
        self.init_mediator()

        expected_denyperm = '-%s:fullcontrol' % constants.USERNAME

        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.CIFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_CIFS],
                                    [],
                                    [constants.DELETE_RULE_USER],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                allowperm=expected_denyperm,
                                comment=constants.EXPECTED_COMMENT,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE)

        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_allow_ip_access_cifs(self):
        """"Allow ip access to cifs share."""
        self.init_mediator()

        expected_allowip = '+%s' % constants.EXPECTED_IP_1234

        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.CIFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_NFS],
                                    [constants.ADD_RULE_IP],
                                    [],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                allowip=expected_allowip,
                                comment=constants.EXPECTED_COMMENT,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_deny_ip_access_cifs(self):
        """"Deny ip access to cifs share."""
        self.init_mediator()

        expected_denyip = '-%s' % constants.EXPECTED_IP_1234

        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.CIFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_NFS],
                                    [],
                                    [constants.DELETE_RULE_IP],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                allowip=expected_denyip,
                                comment=constants.EXPECTED_COMMENT,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_allow_ip_access_nfs(self):
        """"Allow ip access to nfs share."""
        self.init_mediator()
        already_exists = (hpe3parmediator.IP_ALREADY_EXISTS %
                          constants.EXPECTED_IP_1234)
        self.mock_client.setfshare.side_effect = ([], [already_exists])

        expected_clientip = '+%s' % constants.EXPECTED_IP_1234

        for _ in range(2):  # Test 2nd allow w/ already exists message.
            self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                        constants.EXPECTED_SHARE_ID,
                                        constants.NFS,
                                        constants.EXPECTED_EXTRA_SPECS,
                                        [constants.ACCESS_RULE_NFS],
                                        [constants.ADD_RULE_IP],
                                        [],
                                        constants.EXPECTED_FPG,
                                        constants.EXPECTED_VFS)

        expected_calls = 2 * [
            mock.call.setfshare(constants.NFS.lower(),
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                clientip=expected_clientip,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE,
                                comment=constants.EXPECTED_COMMENT),
        ]

        self.mock_client.assert_has_calls(expected_calls, any_order=True)

    def test_mediator_deny_ip_access_nfs(self):
        """"Deny ip access to nfs share."""
        self.init_mediator()

        expected_clientip = '-%s' % constants.EXPECTED_IP_1234

        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.NFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_NFS],
                                    [],
                                    [constants.DELETE_RULE_IP],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.NFS.lower(),
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                clientip=expected_clientip,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE,
                                comment=constants.EXPECTED_COMMENT)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_deny_ip_ro_access_nfs_legacy(self):
        self.init_mediator()

        # Fail to find share with new naming. Succeed finding legacy naming.
        legacy = {
            'shareName': 'foo_name',
            'fstoreName': 'foo_fstore',
            'comment': 'foo_comment',
            'sharePath': 'foo/.snapshot/foo',
        }
        fshares = (None, legacy)
        mock_find_fshare = self.mock_object(self.mediator,
                                            '_find_fshare',
                                            mock.Mock(side_effect=fshares))

        expected_clientip = '-%s' % constants.EXPECTED_IP_1234

        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.NFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_NFS],
                                    [],
                                    [constants.DELETE_RULE_IP_RO],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.NFS.lower(),
                                constants.EXPECTED_VFS,
                                legacy['shareName'],
                                clientip=expected_clientip,
                                fpg=constants.EXPECTED_FPG,
                                fstore=legacy['fstoreName'],
                                comment=legacy['comment'])
        ]
        self.mock_client.assert_has_calls(expected_calls)

        expected_find_fshare_calls = [
            mock.call(constants.EXPECTED_PROJECT_ID,
                      constants.EXPECTED_SHARE_ID,
                      constants.NFS_LOWER,
                      constants.EXPECTED_FPG,
                      constants.EXPECTED_VFS,
                      readonly=True),
            mock.call(constants.EXPECTED_PROJECT_ID,
                      constants.EXPECTED_SHARE_ID,
                      constants.NFS_LOWER,
                      constants.EXPECTED_FPG,
                      constants.EXPECTED_VFS,
                      readonly=False),
        ]
        mock_find_fshare.assert_has_calls(expected_find_fshare_calls)

    def test_mediator_allow_user_access_nfs(self):
        """"Allow user access to nfs share is not supported."""
        self.init_mediator()

        self.assertRaises(exception.HPE3ParInvalid,
                          self.mediator.update_access,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_EXTRA_SPECS,
                          [constants.ACCESS_RULE_NFS],
                          [constants.ADD_RULE_USER],
                          [],
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def test_mediator_allow_access_bad_proto(self):
        """"Allow user access to unsupported protocol."""
        self.init_mediator()

        self.assertRaises(exception.InvalidShareAccess,
                          self.mediator.update_access,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          'unsupported_other_protocol',
                          constants.EXPECTED_EXTRA_SPECS,
                          [constants.ACCESS_RULE_NFS],
                          [constants.ADD_RULE_IP],
                          [],
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def test_mediator_allow_access_bad_type(self):
        """"Allow user access to unsupported access type."""
        self.init_mediator()

        self.assertRaises(exception.InvalidInput,
                          self.mediator.update_access,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.CIFS,
                          constants.EXPECTED_EXTRA_SPECS,
                          [constants.ACCESS_RULE_NFS],
                          [constants.ADD_RULE_BAD_TYPE],
                          [],
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def test_mediator_allow_access_missing_nfs_share(self):
        self.init_mediator()
        mock_find_fshare = self.mock_object(self.mediator,
                                            '_find_fshare',
                                            mock.Mock(return_value=None))

        self.assertRaises(exception.HPE3ParInvalid,
                          self.mediator.update_access,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_EXTRA_SPECS,
                          [constants.ACCESS_RULE_NFS],
                          [constants.ADD_RULE_IP],
                          [],
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

        expected_calls = [
            mock.call(constants.EXPECTED_PROJECT_ID,
                      constants.EXPECTED_SHARE_ID,
                      constants.NFS_LOWER,
                      constants.EXPECTED_FPG,
                      constants.EXPECTED_VFS,
                      readonly=False),
            mock.call(constants.EXPECTED_PROJECT_ID,
                      constants.EXPECTED_SHARE_ID,
                      constants.NFS_LOWER,
                      constants.EXPECTED_FPG,
                      constants.EXPECTED_VFS,
                      readonly=True),
        ]
        mock_find_fshare.assert_has_calls(expected_calls)

    def test_mediator_allow_nfs_ro_access(self):
        self.init_mediator()
        getfshare_result = {
            'shareName': 'foo_ro_name',
            'fstoreName': 'foo_fstore',
            'shareDir': 'foo_dir',
            'comment': 'foo_comment',
        }
        findings = (None, getfshare_result)
        mock_find_fshare = self.mock_object(self.mediator,
                                            '_find_fshare',
                                            mock.Mock(side_effect=findings))
        self.mock_client.getfshare.return_value = {
            'total': 1,
            'members': [getfshare_result],
            'message': None,
        }

        share_id = 'foo'

        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    share_id,
                                    constants.NFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_NFS],
                                    [constants.ADD_RULE_IP_RO],
                                    [],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        expected_calls = [
            mock.call(constants.EXPECTED_PROJECT_ID,
                      share_id,
                      constants.NFS_LOWER,
                      constants.EXPECTED_FPG,
                      constants.EXPECTED_VFS,
                      readonly=True),
            mock.call(constants.EXPECTED_PROJECT_ID,
                      share_id,
                      constants.NFS_LOWER,
                      constants.EXPECTED_FPG,
                      constants.EXPECTED_VFS,
                      readonly=False),
        ]
        mock_find_fshare.assert_has_calls(expected_calls)

        ro_share = 'osf-ro-%s' % share_id

        expected_calls = [
            mock.call.createfshare(constants.NFS_LOWER,
                                   constants.EXPECTED_VFS,
                                   ro_share,
                                   clientip=constants.EXPECTED_IP_127_2,
                                   comment=getfshare_result['comment'],
                                   fpg=constants.EXPECTED_FPG,
                                   fstore=getfshare_result['fstoreName'],
                                   options='ro,no_root_squash,insecure',
                                   sharedir=getfshare_result['shareDir']),
            mock.call.getfshare(constants.NFS_LOWER,
                                ro_share,
                                fstore=getfshare_result['fstoreName'],
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS),
            mock.call.setfshare(constants.NFS_LOWER,
                                constants.EXPECTED_VFS,
                                getfshare_result['shareName'],
                                clientip='+%s' % constants.EXPECTED_IP_1234,
                                comment=getfshare_result['comment'],
                                fpg=constants.EXPECTED_FPG,
                                fstore=getfshare_result['fstoreName']),
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_deny_access_missing_nfs_share(self):
        self.init_mediator()
        mock_find_fshare = self.mock_object(self.mediator,
                                            '_find_fshare',
                                            mock.Mock(return_value=None))

        self.mediator.update_access(constants.EXPECTED_PROJECT_ID,
                                    constants.EXPECTED_SHARE_ID,
                                    constants.NFS,
                                    constants.EXPECTED_EXTRA_SPECS,
                                    [constants.ACCESS_RULE_NFS],
                                    [],
                                    [constants.DELETE_RULE_IP],
                                    constants.EXPECTED_FPG,
                                    constants.EXPECTED_VFS)

        expected_calls = [
            mock.call(constants.EXPECTED_PROJECT_ID,
                      constants.EXPECTED_SHARE_ID,
                      constants.NFS_LOWER,
                      constants.EXPECTED_FPG,
                      constants.EXPECTED_VFS,
                      readonly=False),
        ]
        mock_find_fshare.assert_has_calls(expected_calls)

    @ddt.data((hpe3parmediator.ALLOW, 'ip', True,
               ['IP address foo already exists']),
              (hpe3parmediator.ALLOW, 'ip', False,
               ['Another share already exists for this path and client']),
              (hpe3parmediator.ALLOW, 'user', True,
               ['"allow" permission already exists for "foo"']),
              (hpe3parmediator.DENY, 'ip', True,
               ['foo does not exist, cannot be removed']),
              (hpe3parmediator.DENY, 'user', True,
               ['foo:fullcontrol" does not exist, cannot delete it.']),
              (hpe3parmediator.DENY, 'user', False,
               ['SMB share osf-foo does not exist']),
              (hpe3parmediator.ALLOW, 'ip', True, ['\r']),
              (hpe3parmediator.ALLOW, 'user', True, ['\r']),
              (hpe3parmediator.DENY, 'ip', True, ['\r']),
              (hpe3parmediator.DENY, 'user', True, ['\r']),
              (hpe3parmediator.ALLOW, 'ip', True, []),
              (hpe3parmediator.ALLOW, 'user', True, []),
              (hpe3parmediator.DENY, 'ip', True, []),
              (hpe3parmediator.DENY, 'user', True, []))
    @ddt.unpack
    def test_ignore_benign_access_results(self, access, access_type,
                                          expect_false, results):

        returned = self.mediator.ignore_benign_access_results(
            access, access_type, 'foo', results)

        if expect_false:
            self.assertFalse(returned)
        else:
            self.assertEqual(results, returned)

    @ddt.data((2, 1, True),
              (2, 1, False),
              (1, 2, True),
              (1, 2, False),
              (1024, 2048, True),
              (1024, 2048, False),
              (2048, 1024, True),
              (2048, 1024, False),
              (99999999, 1, True),
              (99999999, 1, False),
              (1, 99999999, True),
              (1, 99999999, False),
              )
    @ddt.unpack
    def test_mediator_resize_share(self, new_size, old_size, fstore_per_share):
        self.init_mediator()
        fstore = 'foo_fstore'
        mock_find_fstore = self.mock_object(self.mediator,
                                            '_find_fstore',
                                            mock.Mock(return_value=fstore))
        fstore_init_size = int(
            constants.GET_FSQUOTA['members'][0]['hardBlock'])
        self.mediator.hpe3par_fstore_per_share = fstore_per_share

        if fstore_per_share:
            expected_capacity = new_size * units.Ki
        else:
            expected_capacity = (
                (new_size - old_size) * units.Ki + fstore_init_size)

        self.mediator.resize_share(
            constants.EXPECTED_PROJECT_ID,
            constants.EXPECTED_SHARE_ID,
            constants.NFS,
            new_size,
            old_size,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS)

        mock_find_fstore.assert_called_with(constants.EXPECTED_PROJECT_ID,
                                            constants.EXPECTED_SHARE_ID,
                                            constants.NFS,
                                            constants.EXPECTED_FPG,
                                            constants.EXPECTED_VFS,
                                            allow_cross_protocol=False)
        self.mock_client.setfsquota.assert_called_with(
            constants.EXPECTED_VFS,
            fpg=constants.EXPECTED_FPG,
            fstore=fstore,
            scapacity=six.text_type(expected_capacity),
            hcapacity=six.text_type(expected_capacity))

    @ddt.data(['This is a fake setfsquota returned error'], Exception('boom'))
    def test_mediator_resize_share_setfsquota_side_effects(self, side_effect):
        self.init_mediator()
        fstore_init_size = int(
            constants.GET_FSQUOTA['members'][0]['hardBlock'])
        fstore = 'foo_fstore'
        new_size = 2
        old_size = 1
        expected_capacity = (new_size - old_size) * units.Ki + fstore_init_size
        mock_find_fstore = self.mock_object(self.mediator,
                                            '_find_fstore',
                                            mock.Mock(return_value=fstore))
        self.mock_client.setfsquota.side_effect = side_effect

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.resize_share,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          new_size,
                          old_size,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

        mock_find_fstore.assert_called_with(constants.EXPECTED_PROJECT_ID,
                                            constants.EXPECTED_SHARE_ID,
                                            constants.NFS,
                                            constants.EXPECTED_FPG,
                                            constants.EXPECTED_VFS,
                                            allow_cross_protocol=False)
        self.mock_client.setfsquota.assert_called_with(
            constants.EXPECTED_VFS,
            fpg=constants.EXPECTED_FPG,
            fstore=fstore,
            scapacity=six.text_type(expected_capacity),
            hcapacity=six.text_type(expected_capacity))

    def test_mediator_resize_share_not_found(self):
        self.init_mediator()
        mock_find_fshare = self.mock_object(self.mediator,
                                            '_find_fshare',
                                            mock.Mock(return_value=None))

        self.assertRaises(exception.InvalidShare,
                          self.mediator.resize_share,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          999,
                          99,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

        mock_find_fshare.assert_called_with(constants.EXPECTED_PROJECT_ID,
                                            constants.EXPECTED_SHARE_ID,
                                            constants.NFS,
                                            constants.EXPECTED_FPG,
                                            constants.EXPECTED_VFS,
                                            allow_cross_protocol=False)

    @ddt.data((('nfs', 'NFS', 'nFs'), 'smb'),
              (('smb', 'SMB', 'SmB', 'CIFS', 'cifs', 'CiFs'), 'nfs'))
    @ddt.unpack
    def test_other_protocol(self, protocols, expected_other):
        for protocol in protocols:
            self.assertEqual(expected_other,
                             hpe3parmediator.HPE3ParMediator().other_protocol(
                                 protocol))

    @ddt.data('', 'bogus')
    def test_other_protocol_exception(self, protocol):
        self.assertRaises(exception.InvalidShareAccess,
                          hpe3parmediator.HPE3ParMediator().other_protocol,
                          protocol)

    @ddt.data(('osf-uid', None, None, 'osf-uid'),
              ('uid', None, True, 'osf-ro-uid'),
              ('uid', None, False, 'osf-uid'),
              ('uid', 'smb', True, 'osf-smb-ro-uid'),
              ('uid', 'smb', False, 'osf-smb-uid'),
              ('uid', 'nfs', True, 'osf-nfs-ro-uid'),
              ('uid', 'nfs', False, 'osf-nfs-uid'))
    @ddt.unpack
    def test_ensure_prefix(self, uid, protocol, readonly, expected):
        self.assertEqual(expected,
                         hpe3parmediator.HPE3ParMediator().ensure_prefix(
                             uid, protocol=protocol, readonly=readonly))

    def test_find_fstore_search(self):
        self.init_mediator()

        mock_find_fshare = self.mock_object(self.mediator,
                                            '_find_fshare',
                                            mock.Mock(return_value=None))

        result = self.mediator._find_fstore(constants.EXPECTED_PROJECT_ID,
                                            constants.EXPECTED_SHARE_ID,
                                            constants.NFS,
                                            constants.EXPECTED_FPG,
                                            constants.EXPECTED_VFS)

        mock_find_fshare.assert_called_once_with(constants.EXPECTED_PROJECT_ID,
                                                 constants.EXPECTED_SHARE_ID,
                                                 constants.NFS,
                                                 constants.EXPECTED_FPG,
                                                 constants.EXPECTED_VFS,
                                                 allow_cross_protocol=False)
        self.assertIsNone(result)

    def test_find_fstore_search_xproto(self):
        self.init_mediator()

        mock_find_fshare = self.mock_object(self.mediator,
                                            '_find_fshare_with_proto',
                                            mock.Mock(return_value=None))

        result = self.mediator._find_fstore(constants.EXPECTED_PROJECT_ID,
                                            constants.EXPECTED_SHARE_ID,
                                            constants.NFS,
                                            constants.EXPECTED_FPG,
                                            constants.EXPECTED_VFS,
                                            allow_cross_protocol=True)

        expected_calls = [
            mock.call(constants.EXPECTED_PROJECT_ID,
                      constants.EXPECTED_SHARE_ID,
                      constants.NFS,
                      constants.EXPECTED_FPG,
                      constants.EXPECTED_VFS,
                      readonly=False),
            mock.call(constants.EXPECTED_PROJECT_ID,
                      constants.EXPECTED_SHARE_ID,
                      constants.SMB_LOWER,
                      constants.EXPECTED_FPG,
                      constants.EXPECTED_VFS,
                      readonly=False),
        ]
        mock_find_fshare.assert_has_calls(expected_calls)
        self.assertIsNone(result)

    def test_find_fshare_search(self):
        self.init_mediator()

        self.mock_client.getfshare.return_value = {}

        result = self.mediator._find_fshare(constants.EXPECTED_PROJECT_ID,
                                            constants.EXPECTED_SHARE_ID,
                                            constants.NFS,
                                            constants.EXPECTED_FPG,
                                            constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.getfshare(constants.NFS_LOWER,
                                constants.EXPECTED_SHARE_ID,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_PROJECT_ID),
            mock.call.getfshare(constants.NFS_LOWER,
                                constants.EXPECTED_SHARE_ID,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_SHARE_ID),
            mock.call.getfshare(constants.NFS_LOWER,
                                constants.EXPECTED_SHARE_ID,
                                fpg=constants.EXPECTED_FPG),
            mock.call.getfshare(constants.NFS_LOWER,
                                constants.EXPECTED_SHARE_ID),
        ]
        self.mock_client.assert_has_calls(expected_calls)
        self.assertIsNone(result)

    def test_find_fshare_exception(self):
        self.init_mediator()

        self.mock_client.getfshare.side_effect = Exception('test unexpected')

        self.assertRaises(exception.ShareBackendException,
                          self.mediator._find_fshare,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

        self.mock_client.getfshare.assert_called_once_with(
            constants.NFS_LOWER,
            constants.EXPECTED_SHARE_ID,
            fpg=constants.EXPECTED_FPG,
            vfs=constants.EXPECTED_VFS,
            fstore=constants.EXPECTED_PROJECT_ID)

    def test_find_fshare_hit(self):
        self.init_mediator()

        expected_result = {'shareName': 'hit'}
        self.mock_client.getfshare.return_value = {
            'total': 1,
            'members': [expected_result]
        }

        result = self.mediator._find_fshare(constants.EXPECTED_PROJECT_ID,
                                            constants.EXPECTED_SHARE_ID,
                                            constants.NFS,
                                            constants.EXPECTED_FPG,
                                            constants.EXPECTED_VFS)

        self.mock_client.getfshare.assert_called_once_with(
            constants.NFS_LOWER,
            constants.EXPECTED_SHARE_ID,
            fpg=constants.EXPECTED_FPG,
            vfs=constants.EXPECTED_VFS,
            fstore=constants.EXPECTED_PROJECT_ID),
        self.assertEqual(expected_result, result)

    def test_find_fsnap_search(self):
        self.init_mediator()

        self.mock_client.getfsnap.return_value = {}

        result = self.mediator._find_fsnap(constants.EXPECTED_PROJECT_ID,
                                           constants.EXPECTED_SHARE_ID,
                                           constants.NFS,
                                           constants.EXPECTED_SNAP_ID,
                                           constants.EXPECTED_FPG,
                                           constants.EXPECTED_VFS)

        expected_snap_pattern = '*_%s' % constants.EXPECTED_SNAP_ID

        expected_calls = [
            mock.call.getfsnap(expected_snap_pattern,
                               vfs=constants.EXPECTED_VFS,
                               fpg=constants.EXPECTED_FPG,
                               pat=True,
                               fstore=constants.EXPECTED_PROJECT_ID),
            mock.call.getfsnap(expected_snap_pattern,
                               vfs=constants.EXPECTED_VFS,
                               fpg=constants.EXPECTED_FPG,
                               pat=True,
                               fstore=constants.EXPECTED_SHARE_ID),
            mock.call.getfsnap(expected_snap_pattern,
                               fpg=constants.EXPECTED_FPG,
                               pat=True),
            mock.call.getfsnap(expected_snap_pattern, pat=True),
        ]
        self.mock_client.assert_has_calls(expected_calls)
        self.assertIsNone(result)

    def test_find_fsnap_exception(self):
        self.init_mediator()

        self.mock_client.getfsnap.side_effect = Exception('test unexpected')

        self.assertRaises(exception.ShareBackendException,
                          self.mediator._find_fsnap,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.EXPECTED_SNAP_ID,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

        expected_snap_pattern = '*_%s' % constants.EXPECTED_SNAP_ID

        self.mock_client.getfsnap.assert_called_once_with(
            expected_snap_pattern,
            vfs=constants.EXPECTED_VFS,
            fpg=constants.EXPECTED_FPG,
            pat=True,
            fstore=constants.EXPECTED_PROJECT_ID)

    def test_find_fsnap_hit(self):
        self.init_mediator()

        expected_result = {'snapName': 'hit'}
        self.mock_client.getfsnap.return_value = {
            'total': 1,
            'members': [expected_result]
        }

        result = self.mediator._find_fsnap(constants.EXPECTED_PROJECT_ID,
                                           constants.EXPECTED_SHARE_ID,
                                           constants.NFS,
                                           constants.EXPECTED_SNAP_ID,
                                           constants.EXPECTED_FPG,
                                           constants.EXPECTED_VFS)

        expected_snap_pattern = '*_%s' % constants.EXPECTED_SNAP_ID

        self.mock_client.getfsnap.assert_called_once_with(
            expected_snap_pattern,
            vfs=constants.EXPECTED_VFS,
            fpg=constants.EXPECTED_FPG,
            pat=True,
            fstore=constants.EXPECTED_PROJECT_ID)

        self.assertEqual(expected_result, result)

    def test_fsip_exists(self):
        self.init_mediator()

        # Make the result member a superset of the fsip items.
        fsip_plus = constants.EXPECTED_FSIP.copy()
        fsip_plus.update({'k': 'v', 'k2': 'v2'})

        self.mock_client.getfsip.return_value = {
            'total': 3,
            'members': [{'bogus1': 1}, fsip_plus, {'bogus2': '2'}]
        }

        self.assertTrue(self.mediator.fsip_exists(constants.EXPECTED_FSIP))

        self.mock_client.getfsip.assert_called_once_with(
            constants.EXPECTED_VFS,
            fpg=constants.EXPECTED_FPG)

    def test_fsip_does_not_exist(self):
        self.init_mediator()

        self.mock_client.getfsip.return_value = {
            'total': 3,
            'members': [{'bogus1': 1}, constants.OTHER_FSIP, {'bogus2': '2'}]
        }

        self.assertFalse(self.mediator.fsip_exists(constants.EXPECTED_FSIP))

        self.mock_client.getfsip.assert_called_once_with(
            constants.EXPECTED_VFS,
            fpg=constants.EXPECTED_FPG)

    def test_fsip_exists_exception(self):
        self.init_mediator()

        class FakeException(Exception):
            pass

        self.mock_client.getfsip.side_effect = FakeException()

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.fsip_exists,
                          constants.EXPECTED_FSIP)

        self.mock_client.getfsip.assert_called_once_with(
            constants.EXPECTED_VFS,
            fpg=constants.EXPECTED_FPG)

    def test_create_fsip_success(self):
        self.init_mediator()

        # Make the result member a superset of the fsip items.
        fsip_plus = constants.EXPECTED_FSIP.copy()
        fsip_plus.update({'k': 'v', 'k2': 'v2'})

        self.mock_client.getfsip.return_value = {
            'total': 3,
            'members': [{'bogus1': 1}, fsip_plus, {'bogus2': '2'}]
        }

        self.mediator.create_fsip(constants.EXPECTED_IP_1234,
                                  constants.EXPECTED_SUBNET,
                                  constants.EXPECTED_VLAN_TAG,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)

        self.mock_client.getfsip.assert_called_once_with(
            constants.EXPECTED_VFS,
            fpg=constants.EXPECTED_FPG)

        expected_calls = [
            mock.call.createfsip(constants.EXPECTED_IP_1234,
                                 constants.EXPECTED_SUBNET,
                                 constants.EXPECTED_VFS,
                                 fpg=constants.EXPECTED_FPG,
                                 vlantag=constants.EXPECTED_VLAN_TAG),
            mock.call.getfsip(constants.EXPECTED_VFS,
                              fpg=constants.EXPECTED_FPG),
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_create_fsip_exception(self):
        self.init_mediator()

        class FakeException(Exception):
            pass

        self.mock_client.createfsip.side_effect = FakeException()

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_fsip,
                          constants.EXPECTED_IP_1234,
                          constants.EXPECTED_SUBNET,
                          constants.EXPECTED_VLAN_TAG,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

        self.mock_client.createfsip.assert_called_once_with(
            constants.EXPECTED_IP_1234,
            constants.EXPECTED_SUBNET,
            constants.EXPECTED_VFS,
            fpg=constants.EXPECTED_FPG,
            vlantag=constants.EXPECTED_VLAN_TAG)

    def test_create_fsip_get_none(self):
        self.init_mediator()

        self.mock_client.getfsip.return_value = {'members': []}

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_fsip,
                          constants.EXPECTED_IP_1234,
                          constants.EXPECTED_SUBNET,
                          constants.EXPECTED_VLAN_TAG,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.createfsip(constants.EXPECTED_IP_1234,
                                 constants.EXPECTED_SUBNET,
                                 constants.EXPECTED_VFS,
                                 fpg=constants.EXPECTED_FPG,
                                 vlantag=constants.EXPECTED_VLAN_TAG),
            mock.call.getfsip(constants.EXPECTED_VFS,
                              fpg=constants.EXPECTED_FPG),
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_remove_fsip_success(self):
        self.init_mediator()

        self.mock_client.getfsip.return_value = {
            'members': [constants.OTHER_FSIP]
        }

        self.mediator.remove_fsip(constants.EXPECTED_IP_1234,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.removefsip(constants.EXPECTED_VFS,
                                 constants.EXPECTED_IP_1234,
                                 fpg=constants.EXPECTED_FPG),
            mock.call.getfsip(constants.EXPECTED_VFS,
                              fpg=constants.EXPECTED_FPG),
        ]
        self.mock_client.assert_has_calls(expected_calls)

    @ddt.data(('ip', None),
              ('ip', ''),
              (None, 'vfs'),
              ('', 'vfs'),
              (None, None),
              ('', ''))
    @ddt.unpack
    def test_remove_fsip_without_ip_or_vfs(self, ip, vfs):
        self.init_mediator()
        self.mediator.remove_fsip(ip, constants.EXPECTED_FPG, vfs)
        self.assertFalse(self.mock_client.removefsip.called)

    def test_remove_fsip_not_gone(self):
        self.init_mediator()

        self.mock_client.getfsip.return_value = {
            'members': [constants.EXPECTED_FSIP]
        }

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.remove_fsip,
                          constants.EXPECTED_IP_1234,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.removefsip(constants.EXPECTED_VFS,
                                 constants.EXPECTED_IP_1234,
                                 fpg=constants.EXPECTED_FPG),
            mock.call.getfsip(constants.EXPECTED_VFS,
                              fpg=constants.EXPECTED_FPG),
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_remove_fsip_exception(self):
        self.init_mediator()

        class FakeException(Exception):
            pass

        self.mock_client.removefsip.side_effect = FakeException()

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.remove_fsip,
                          constants.EXPECTED_IP_1234,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

        self.mock_client.removefsip.assert_called_once_with(
            constants.EXPECTED_VFS,
            constants.EXPECTED_IP_1234,
            fpg=constants.EXPECTED_FPG)

    def test__create_mount_directory(self):
        self.init_mediator()

        mount_location = '/mnt/foo'
        self.mediator._create_mount_directory(mount_location)

        utils.execute.assert_called_with('mkdir', mount_location,
                                         run_as_root=True)

    def test__create_mount_directory_error(self):
        self.init_mediator()

        self.mock_object(utils, 'execute',
                         mock.Mock(side_effect=Exception('mkdir error.')))
        mock_log = self.mock_object(hpe3parmediator, 'LOG')

        mount_location = '/mnt/foo'
        self.mediator._create_mount_directory(mount_location)
        utils.execute.assert_called_with('mkdir', mount_location,
                                         run_as_root=True)

        # Warning is logged (no exception thrown).
        self.assertTrue(mock_log.warning.called)

    def test__mount_super_share(self):
        self.init_mediator()

        # Test mounting NFS share.
        protocol = 'nfs'
        mount_location = '/mnt/foo'
        fpg = 'foo-fpg'
        vfs = 'bar-vfs'
        fstore = 'fstore'
        mount_path = '%s:/%s/%s/%s/' % (constants.EXPECTED_IP_10203040, fpg,
                                        vfs, fstore)
        self.mediator._mount_super_share(protocol, mount_location, fpg, vfs,
                                         fstore,
                                         constants.EXPECTED_IP_10203040)

        utils.execute.assert_called_with('mount', '-t', protocol, mount_path,
                                         mount_location, run_as_root=True)

        # Test mounting CIFS share.
        protocol = 'smb'
        mount_path = '//%s/%s/' % (constants.EXPECTED_IP_10203040,
                                   constants.EXPECTED_SUPER_SHARE)
        user = 'username=%s,password=%s,domain=%s' % (
            constants.USERNAME, constants.PASSWORD,
            constants.EXPECTED_CIFS_DOMAIN)
        self.mediator._mount_super_share(protocol, mount_location, fpg, vfs,
                                         fstore,
                                         constants.EXPECTED_IP_10203040)

        utils.execute.assert_called_with('mount', '-t', 'cifs', mount_path,
                                         mount_location, '-o', user,
                                         run_as_root=True)

    def test__mount_super_share_error(self):
        self.init_mediator()

        self.mock_object(utils, 'execute',
                         mock.Mock(side_effect=Exception('mount error.')))
        mock_log = self.mock_object(hpe3parmediator, 'LOG')

        protocol = 'nfs'
        mount_location = '/mnt/foo'
        fpg = 'foo-fpg'
        vfs = 'bar-vfs'
        fstore = 'fstore'
        self.mediator._mount_super_share(protocol, mount_location, fpg, vfs,
                                         fstore,
                                         constants.EXPECTED_IP_10203040)

        # Warning is logged (no exception thrown).
        self.assertTrue(mock_log.warning.called)

    def test__delete_share_directory(self):
        self.init_mediator()

        mount_location = '/mnt/foo'
        self.mediator._delete_share_directory(mount_location)

        utils.execute.assert_called_with('rm', '-rf', mount_location,
                                         run_as_root=True)

    def test__delete_share_directory_error(self):
        self.init_mediator()

        self.mock_object(utils, 'execute',
                         mock.Mock(side_effect=Exception('rm error.')))
        mock_log = self.mock_object(hpe3parmediator, 'LOG')

        mount_location = '/mnt/foo'
        self.mediator._delete_share_directory(mount_location)

        # Warning is logged (no exception thrown).
        self.assertTrue(mock_log.warning.called)

    def test__unmount_share(self):
        self.init_mediator()

        mount_dir = '/mnt/foo'
        self.mediator._unmount_share(mount_dir)

        utils.execute.assert_called_with('umount', mount_dir, run_as_root=True)

    def test__unmount_share_error(self):
        self.init_mediator()

        self.mock_object(utils, 'execute',
                         mock.Mock(side_effect=Exception('umount error.')))
        mock_log = self.mock_object(hpe3parmediator, 'LOG')

        mount_dir = '/mnt/foo'
        self.mediator._unmount_share(mount_dir)

        # Warning is logged (no exception thrown).
        self.assertTrue(mock_log.warning.called)

    def test__delete_file_tree_no_config_options(self):
        self.init_mediator()

        mock_log = self.mock_object(hpe3parmediator, 'LOG')

        self.mediator.hpe3par_cifs_admin_access_username = None
        self.mediator._delete_file_tree(
            constants.EXPECTED_SHARE_ID,
            constants.SMB_LOWER,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            constants.EXPECTED_FSTORE,
            constants.EXPECTED_SHARE_IP)

        # Warning is logged (no exception thrown).
        self.assertTrue(mock_log.warning.called)

    def test__create_super_share_createfshare_exception(self):
        self.init_mediator()

        self.mock_client.createfshare.side_effect = (
            Exception("createfshare error."))

        self.assertRaises(
            exception.ShareBackendException,
            self.mediator._create_super_share,
            constants.NFS_LOWER,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            constants.EXPECTED_FSTORE)

    def test__create_super_share_setfshare_exception(self):
        self.init_mediator()

        self.mock_client.setfshare.side_effect = (
            Exception("setfshare error."))

        self.assertRaises(
            exception.ShareBackendException,
            self.mediator._create_super_share,
            constants.SMB_LOWER,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            constants.EXPECTED_FSTORE)

    def test__revoke_admin_smb_access_error(self):
        self.init_mediator()

        self.mock_client.setfshare.side_effect = (
            Exception("setfshare error"))

        self.assertRaises(
            exception.ShareBackendException,
            self.mediator._revoke_admin_smb_access,
            constants.SMB_LOWER,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS,
            constants.EXPECTED_FSTORE,
            constants.EXPECTED_COMMENT)

    def test_build_export_locations_bad_protocol(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self.mediator.build_export_locations,
                          "BOGUS",
                          [constants.EXPECTED_IP_1234],
                          constants.EXPECTED_SHARE_PATH)

    def test_build_export_locations_bad_ip(self):
        self.assertRaises(exception.InvalidInput,
                          self.mediator.build_export_locations,
                          constants.NFS,
                          None,
                          None)

    def test_build_export_locations_bad_path(self):
        self.assertRaises(exception.InvalidInput,
                          self.mediator.build_export_locations,
                          constants.NFS,
                          [constants.EXPECTED_IP_1234],
                          None)


class OptionMatcher(object):
    """Options string order can vary. Compare as lists."""

    def __init__(self, assert_func, expected_string):
        self.assert_func = assert_func
        self.expected = expected_string.split(',')

    def __eq__(self, actual_string):
        actual = actual_string.split(',')
        self.assert_func(sorted(self.expected), sorted(actual))
        return True
