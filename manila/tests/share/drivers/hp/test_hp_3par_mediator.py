# Copyright 2015 Hewlett Packard Development Company, L.P.
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
if 'hp3parclient' not in sys.modules:
    sys.modules['hp3parclient'] = mock.Mock()

from manila import exception
from manila.share.drivers.hp import hp_3par_mediator as hp3parmediator
from manila import test
from manila.tests.share.drivers.hp import test_hp_3par_constants as constants

from oslo_utils import units
import six

CLIENT_VERSION_MIN_OK = hp3parmediator.MIN_CLIENT_VERSION
TEST_WSAPI_VERSION_STR = '30201292'


@ddt.ddt
class HP3ParMediatorTestCase(test.TestCase):

    def setUp(self):
        super(HP3ParMediatorTestCase, self).setUp()

        # This is the fake client to use.
        self.mock_client = mock.Mock()

        # Take over the hp3parclient module and stub the constructor.
        hp3parclient = sys.modules['hp3parclient']
        hp3parclient.version_tuple = CLIENT_VERSION_MIN_OK

        # Need a fake constructor to return the fake client.
        # This is also be used for constructor error tests.
        self.mock_object(hp3parclient.file_client, 'HP3ParFilePersonaClient')
        self.mock_client_constructor = (
            hp3parclient.file_client.HP3ParFilePersonaClient
        )
        self.mock_client = self.mock_client_constructor()

        # Set the mediator to use in tests.
        self.mediator = hp3parmediator.HP3ParMediator(
            hp3par_username=constants.USERNAME,
            hp3par_password=constants.PASSWORD,
            hp3par_api_url=constants.API_URL,
            hp3par_debug=constants.EXPECTED_HP_DEBUG,
            hp3par_san_ip=constants.EXPECTED_IP_1234,
            hp3par_san_login=constants.SAN_LOGIN,
            hp3par_san_password=constants.SAN_PASSWORD,
            hp3par_san_ssh_port=constants.PORT,
            ssh_conn_timeout=constants.TIMEOUT)

    def test_mediator_no_client(self):
        """Test missing hp3parclient error."""

        self.mock_object(hp3parmediator.HP3ParMediator, 'no_client', None)

        self.assertRaises(exception.HP3ParInvalidClient,
                          self.mediator.do_setup)

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
        """Backend exception during get_vfs_name."""

        self.init_mediator()
        self.mock_client.getvfs.side_effect = Exception('non-manila-except')
        self.assertRaises(exception.ManilaException,
                          self.mediator.get_vfs_name,
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
                          self.mediator.get_vfs_name,
                          fpg=constants.EXPECTED_FPG)
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
                 'sharePath': constants.EXPECTED_SHARE_PATH}]
        }
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
            mock.call.debug_rest(constants.EXPECTED_HP_DEBUG)
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

        mock_log = self.mock_object(hp3parmediator, 'LOG')
        fake_exception = constants.FAKE_EXCEPTION
        self.mock_client.http.unauthenticate.side_effect = fake_exception

        self.mediator._wsapi_logout()

        # Warning is logged (no exception thrown).
        self.assertTrue(mock_log.warning.called)
        expected_calls = [mock.call.http.unauthenticate()]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_client_version_unsupported(self):
        """Try a client with version less than minimum."""

        self.hp3parclient = sys.modules['hp3parclient']
        self.hp3parclient.version_tuple = (CLIENT_VERSION_MIN_OK[0],
                                           CLIENT_VERSION_MIN_OK[1],
                                           CLIENT_VERSION_MIN_OK[2] - 1)
        self.assertRaises(exception.HP3ParInvalidClient,
                          self.init_mediator)

    def test_mediator_client_version_supported(self):
        """Try a client with a version greater than the minimum."""

        # The setup success already tests the min version.  Try version > min.
        self.hp3parclient = sys.modules['hp3parclient']
        self.hp3parclient.version_tuple = (CLIENT_VERSION_MIN_OK[0],
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
            mock.call.debug_rest(constants.EXPECTED_HP_DEBUG)
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
            createfshare_kwargs['allowip'] = '127.0.0.1'

            if client_version < hp3parmediator.MIN_SMB_CA_VERSION:
                smb_opts = (hp3parmediator.ACCESS_BASED_ENUM,
                            hp3parmediator.CACHE)
            else:
                smb_opts = (hp3parmediator.ACCESS_BASED_ENUM,
                            hp3parmediator.CONTINUOUS_AVAIL,
                            hp3parmediator.CACHE)

            for smb_opt in smb_opts:
                opt_value = extra_specs.get('hpe3par:smb_%s' % smb_opt)
                if opt_value:
                    opt_key = hp3parmediator.SMB_EXTRA_SPECS_MAP[smb_opt]
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

    @ddt.data(((3, 2, 1), None, None, None),
              ((3, 2, 1), 'true', None, None),
              ((3, 2, 1), None, 'false', None),
              ((3, 2, 1), None, 'false', None),
              ((3, 2, 1), None, None, 'optimized'),
              ((3, 2, 1), 'true', 'false', 'optimized'),
              ((3, 2, 2), None, None, None),
              ((3, 2, 2), 'true', None, None),
              ((3, 2, 2), None, 'false', None),
              ((3, 2, 2), None, 'false', None),
              ((3, 2, 2), None, None, 'optimized'),
              ((3, 2, 2), 'true', 'false', 'optimized'))
    @ddt.unpack
    def test_mediator_create_cifs_share(self, client_version, abe, ca, cache):
        self.hp3parclient = sys.modules['hp3parclient']
        self.hp3parclient.version_tuple = client_version
        self.init_mediator()

        self.mock_client.getfshare.return_value = {
            'message': None,
            'total': 1,
            'members': [{'shareName': constants.EXPECTED_SHARE_NAME}]
        }

        self.mock_client.getfsquota.return_value = constants.GET_FSQUOTA

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

        self.mock_client.getfsquota.return_value = constants.GET_FSQUOTA

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
            hp3parmediator.MIN_CLIENT_VERSION,
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
        self.mock_client.getfsquota.return_value = constants.GET_FSQUOTA

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
        self.mock_client.getfsquota.return_value = constants.GET_FSQUOTA

        self.assertRaises(exception.ShareBackendException,
                          self.mediator.create_share,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS.lower(),
                          constants.EXPECTED_EXTRA_SPECS,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS,
                          size=constants.EXPECTED_SIZE_1)

    def test_mediator_create_cifs_share_from_snapshot(self):
        self.init_mediator()

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
            constants.NFS,
            constants.EXPECTED_SNAP_ID,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS)

        self.assertEqual(constants.EXPECTED_SHARE_ID, location)

        expected_calls = [
            mock.call.getfsnap('*_%s' % constants.EXPECTED_SNAP_ID,
                               vfs=constants.EXPECTED_VFS,
                               fpg=constants.EXPECTED_FPG,
                               pat=True,
                               fstore=constants.EXPECTED_FSTORE),
            mock.call.createfshare(constants.SMB_LOWER,
                                   constants.EXPECTED_VFS,
                                   constants.EXPECTED_SHARE_ID,
                                   comment=mock.ANY,
                                   fpg=constants.EXPECTED_FPG,
                                   sharedir='.snapshot/%s/%s' % (
                                            constants.EXPECTED_SNAP_ID,
                                            constants.EXPECTED_SHARE_ID),
                                   fstore=constants.EXPECTED_FSTORE,
                                   allowip=constants.EXPECTED_IP_127),
            mock.call.getfshare(constants.SMB_LOWER,
                                constants.EXPECTED_SHARE_ID,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_FSTORE)]

        self.mock_client.assert_has_calls(expected_calls)

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
            constants.NFS,
            constants.EXPECTED_SNAP_ID,
            constants.EXPECTED_FPG,
            constants.EXPECTED_VFS)

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
                                   clientip=constants.EXPECTED_IP_127,
                                   options='ro,no_root_squash,insecure'),
            mock.call.getfshare(constants.NFS_LOWER,
                                constants.EXPECTED_SHARE_ID,
                                fpg=constants.EXPECTED_FPG,
                                vfs=constants.EXPECTED_VFS,
                                fstore=constants.EXPECTED_FSTORE)]

        self.mock_client.assert_has_calls(expected_calls)

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
                          constants.NFS,
                          constants.EXPECTED_SNAP_ID,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def test_mediator_delete_share(self):
        self.init_mediator()

        self.mock_object(self.mediator,
                         '_find_fstore',
                         mock.Mock(return_value=constants.EXPECTED_SHARE_ID))

        self.mediator.delete_share(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.CIFS,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS)

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
        mock_log = self.mock_object(hp3parmediator, 'LOG')

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
            'provisioningType': hp3parmediator.DEDUPE}

        expected_result = {
            'free_capacity_gb': expected_free,
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

    def test_mediator_allow_user_access_cifs(self):
        """"Allow user access to cifs share."""
        self.init_mediator()

        expected_allowperm = '+%s:fullcontrol' % constants.USERNAME

        self.mediator.allow_access(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.CIFS,
                                   constants.USER,
                                   constants.USERNAME,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                allowperm=expected_allowperm,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE)

        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_deny_user_access_cifs(self):
        """"Deny user access to cifs share."""
        self.init_mediator()

        expected_denyperm = '-%s:fullcontrol' % constants.USERNAME

        self.mediator.deny_access(constants.EXPECTED_PROJECT_ID,
                                  constants.EXPECTED_SHARE_ID,
                                  constants.CIFS,
                                  constants.USER,
                                  constants.USERNAME,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                allowperm=expected_denyperm,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE)

        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_allow_ip_access_cifs(self):
        """"Allow ip access to cifs share."""
        self.init_mediator()

        expected_allowip = '+%s' % constants.EXPECTED_IP_1234

        self.mediator.allow_access(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.CIFS,
                                   constants.IP,
                                   constants.EXPECTED_IP_1234,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                allowip=expected_allowip,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_deny_ip_access_cifs(self):
        """"Deny ip access to cifs share."""
        self.init_mediator()

        expected_denyip = '-%s' % constants.EXPECTED_IP_1234

        self.mediator.deny_access(constants.EXPECTED_PROJECT_ID,
                                  constants.EXPECTED_SHARE_ID,
                                  constants.CIFS,
                                  constants.IP,
                                  constants.EXPECTED_IP_1234,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.SMB_LOWER,
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                allowip=expected_denyip,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_allow_ip_access_nfs(self):
        """"Allow ip access to nfs share."""
        self.init_mediator()

        expected_clientip = '+%s' % constants.EXPECTED_IP_1234

        self.mediator.allow_access(constants.EXPECTED_PROJECT_ID,
                                   constants.EXPECTED_SHARE_ID,
                                   constants.NFS,
                                   constants.IP,
                                   constants.EXPECTED_IP_1234,
                                   constants.EXPECTED_FPG,
                                   constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.NFS.lower(),
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                clientip=expected_clientip,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_deny_ip_access_nfs(self):
        """"Deny ip access to nfs share."""
        self.init_mediator()

        expected_clientip = '-%s' % constants.EXPECTED_IP_1234

        self.mediator.deny_access(constants.EXPECTED_PROJECT_ID,
                                  constants.EXPECTED_SHARE_ID,
                                  constants.NFS,
                                  constants.IP,
                                  constants.EXPECTED_IP_1234,
                                  constants.EXPECTED_FPG,
                                  constants.EXPECTED_VFS)

        expected_calls = [
            mock.call.setfshare(constants.NFS.lower(),
                                constants.EXPECTED_VFS,
                                constants.EXPECTED_SHARE_ID,
                                clientip=expected_clientip,
                                fpg=constants.EXPECTED_FPG,
                                fstore=constants.EXPECTED_FSTORE)
        ]
        self.mock_client.assert_has_calls(expected_calls)

    def test_mediator_allow_user_access_nfs(self):
        """"Allow user access to nfs share is not supported."""
        self.init_mediator()

        self.assertRaises(exception.HP3ParInvalid,
                          self.mediator.allow_access,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.NFS,
                          constants.USER,
                          constants.USERNAME,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def test_mediator_allow_access_bad_proto(self):
        """"Allow user access to unsupported protocol."""
        self.init_mediator()

        self.assertRaises(exception.InvalidInput,
                          self.mediator.allow_access,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          'unsupported_other_protocol',
                          constants.USER,
                          constants.USERNAME,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    def test_mediator_allow_access_bad_type(self):
        """"Allow user access to unsupported access type."""
        self.init_mediator()

        self.assertRaises(exception.InvalidInput,
                          self.mediator.allow_access,
                          constants.EXPECTED_PROJECT_ID,
                          constants.EXPECTED_SHARE_ID,
                          constants.CIFS,
                          'unsupported_other_type',
                          constants.USERNAME,
                          constants.EXPECTED_FPG,
                          constants.EXPECTED_VFS)

    @ddt.data((('nfs', 'NFS', 'nFs'), 'smb'),
              (('smb', 'SMB', 'SmB', 'CIFS', 'cifs', 'CiFs'), 'nfs'))
    @ddt.unpack
    def test_other_protocol(self, protocols, expected_other):
        for protocol in protocols:
            self.assertEqual(expected_other,
                             hp3parmediator.HP3ParMediator().other_protocol(
                                 protocol))

    @ddt.data('', 'bogus')
    def test_other_protocol_exception(self, protocol):
        self.assertRaises(exception.InvalidInput,
                          hp3parmediator.HP3ParMediator().other_protocol,
                          protocol)

    @ddt.data(('osf-uid', None, 'osf-uid'),
              ('uid', None, 'osf-uid'),
              ('uid', 'smb', 'osf-smb-uid'),
              ('uid', 'smb', 'osf-smb-uid'))
    @ddt.unpack
    def test_ensure_prefix(self, uid, protocol, expected):
        self.assertEqual(expected,
                         hp3parmediator.HP3ParMediator().ensure_prefix(
                             uid, protocol=protocol))

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
                                                 constants.EXPECTED_VFS)
        self.assertIsNone(result)

    def test_find_fstore_search_xproto(self):
        self.init_mediator()

        mock_find_fshare = self.mock_object(self.mediator,
                                            '_find_fshare',
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
                      constants.EXPECTED_VFS),
            mock.call(constants.EXPECTED_PROJECT_ID,
                      constants.EXPECTED_SHARE_ID,
                      constants.SMB_LOWER,
                      constants.EXPECTED_FPG,
                      constants.EXPECTED_VFS),
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


class OptionMatcher(object):
    """Options string order can vary. Compare as lists."""

    def __init__(self, assert_func, expected_string):
        self.assert_func = assert_func
        self.expected = expected_string.split(',')

    def __eq__(self, actual_string):
        actual = actual_string.split(',')
        self.assert_func(sorted(self.expected), sorted(actual))
        return True
