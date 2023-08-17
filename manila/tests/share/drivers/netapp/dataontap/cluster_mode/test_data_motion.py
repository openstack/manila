# Copyright (c) 2015 Alex Meade.  All rights reserved.
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
import time
from unittest import mock

import ddt
from oslo_config import cfg

from manila import exception
from manila.share import configuration
from manila.share import driver
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.cluster_mode import data_motion
from manila.share.drivers.netapp import options as na_opts
from manila.share.drivers.netapp import utils as na_utils
from manila.share import utils as share_utils
from manila import test
from manila.tests.share.drivers.netapp.dataontap import fakes as fake
from manila.tests.share.drivers.netapp import fakes as na_fakes


CONF = cfg.CONF


@ddt.ddt
class NetAppCDOTDataMotionTestCase(test.TestCase):

    def setUp(self):
        super(NetAppCDOTDataMotionTestCase, self).setUp()
        self.backend = 'backend1'
        self.mock_cmode_client = self.mock_object(client_cmode,
                                                  "NetAppCmodeClient",
                                                  mock.Mock())
        self.config = configuration.Configuration(driver.share_opts,
                                                  config_group=self.backend)
        self.config.append_config_values(na_opts.netapp_cluster_opts)
        self.config.append_config_values(na_opts.netapp_connection_opts)
        self.config.append_config_values(na_opts.netapp_basicauth_opts)
        self.config.append_config_values(na_opts.netapp_transport_opts)
        self.config.append_config_values(na_opts.netapp_support_opts)
        self.config.append_config_values(na_opts.netapp_provisioning_opts)
        self.config.append_config_values(na_opts.netapp_data_motion_opts)
        CONF.set_override("share_backend_name", self.backend,
                          group=self.backend)
        CONF.set_override("netapp_transport_type", "https",
                          group=self.backend)
        CONF.set_override("netapp_login", "fake_user",
                          group=self.backend)
        CONF.set_override("netapp_password", "fake_password",
                          group=self.backend)
        CONF.set_override("netapp_server_hostname", "fake.hostname",
                          group=self.backend)
        CONF.set_override("netapp_server_port", 8866,
                          group=self.backend)
        CONF.set_override("netapp_ssl_cert_path", "/etc/ssl/certs",
                          group=self.backend)

    def test_get_client_for_backend(self):
        self.mock_object(data_motion, "get_backend_configuration",
                         mock.Mock(return_value=self.config))

        data_motion.get_client_for_backend(self.backend)

        self.mock_cmode_client.assert_called_once_with(
            hostname='fake.hostname', password='fake_password',
            username='fake_user', transport_type='https', port=8866,
            ssl_cert_path='/etc/ssl/certs', trace=mock.ANY, vserver=None)

    def test_get_client_for_backend_with_vserver(self):
        self.mock_object(data_motion, "get_backend_configuration",
                         mock.Mock(return_value=self.config))

        CONF.set_override("netapp_vserver", 'fake_vserver',
                          group=self.backend)

        data_motion.get_client_for_backend(self.backend)

        self.mock_cmode_client.assert_called_once_with(
            hostname='fake.hostname', password='fake_password',
            username='fake_user', transport_type='https', port=8866,
            ssl_cert_path='/etc/ssl/certs', trace=mock.ANY,
            vserver='fake_vserver')

    def test_get_client_for_host(self):
        mock_extract_host = self.mock_object(
            share_utils, 'extract_host',
            mock.Mock(return_value=fake.BACKEND_NAME))
        mock_get_client = self.mock_object(
            data_motion, 'get_client_for_backend',
            mock.Mock(return_value=self.mock_cmode_client))

        returned_client = data_motion.get_client_for_host(
            fake.HOST_NAME)

        mock_extract_host.assert_called_once_with(
            fake.HOST_NAME, level='backend_name')
        mock_get_client.assert_called_once_with(fake.BACKEND_NAME)
        self.assertEqual(returned_client, self.mock_cmode_client)

    def test_get_config_for_backend(self):
        self.mock_object(data_motion, "CONF")
        CONF.set_override("netapp_vserver", 'fake_vserver',
                          group=self.backend)
        data_motion.CONF.list_all_sections.return_value = [self.backend]

        config = data_motion.get_backend_configuration(self.backend)

        self.assertEqual('fake_vserver', config.netapp_vserver)

    def test_get_config_for_backend_different_backend_name(self):
        self.mock_object(data_motion, "CONF")
        CONF.set_override("netapp_vserver", 'fake_vserver',
                          group=self.backend)
        CONF.set_override("share_backend_name", "fake_backend_name",
                          group=self.backend)
        data_motion.CONF.list_all_sections.return_value = [self.backend]

        config = data_motion.get_backend_configuration(self.backend)

        self.assertEqual('fake_vserver', config.netapp_vserver)
        self.assertEqual('fake_backend_name', config.share_backend_name)

    @ddt.data([], ['fake_backend1', 'fake_backend2'])
    def test_get_config_for_backend_not_configured(self, conf_sections):
        self.mock_object(data_motion, "CONF")
        data_motion.CONF.list_all_sections.return_value = conf_sections

        self.assertRaises(exception.BadConfigurationException,
                          data_motion.get_backend_configuration,
                          self.backend)


@ddt.ddt
class NetAppCDOTDataMotionSessionTestCase(test.TestCase):

    def setUp(self):
        super(NetAppCDOTDataMotionSessionTestCase, self).setUp()
        self.source_backend = 'backend1'
        self.dest_backend = 'backend2'

        config = configuration.Configuration(driver.share_opts,
                                             config_group=self.source_backend)
        config.append_config_values(na_opts.netapp_cluster_opts)
        config.append_config_values(na_opts.netapp_connection_opts)
        config.append_config_values(na_opts.netapp_basicauth_opts)
        config.append_config_values(na_opts.netapp_transport_opts)
        config.append_config_values(na_opts.netapp_support_opts)
        config.append_config_values(na_opts.netapp_provisioning_opts)
        config.append_config_values(na_opts.netapp_data_motion_opts)

        self.mock_object(data_motion, "get_backend_configuration",
                         mock.Mock(return_value=config))

        self.mock_cmode_client = self.mock_object(client_cmode,
                                                  "NetAppCmodeClient",
                                                  mock.Mock())
        self.dm_session = data_motion.DataMotionSession()
        self.fake_src_share = copy.deepcopy(fake.SHARE)
        self.fake_src_share_server = copy.deepcopy(fake.SHARE_SERVER)
        self.source_vserver = 'source_vserver'
        self.source_backend_name = (
            self.fake_src_share_server['host'].split('@')[1])
        self.fake_src_share_server['backend_details']['vserver_name'] = (
            self.source_vserver
        )
        self.fake_src_share['share_server'] = self.fake_src_share_server
        self.fake_src_share['id'] = 'c02d497a-236c-4852-812a-0d39373e312a'
        self.fake_src_vol_name = 'share_c02d497a_236c_4852_812a_0d39373e312a'
        self.fake_dest_share = copy.deepcopy(fake.SHARE)
        self.fake_dest_share_server = copy.deepcopy(fake.SHARE_SERVER_2)
        self.dest_vserver = 'dest_vserver'
        self.dest_backend_name = (
            self.fake_dest_share_server['host'].split('@')[1])
        self.fake_dest_share_server['backend_details']['vserver_name'] = (
            self.dest_vserver
        )
        self.fake_dest_share['share_server'] = self.fake_dest_share_server
        self.fake_dest_share['id'] = '34fbaf57-745d-460f-8270-3378c2945e30'
        self.fake_dest_vol_name = 'share_34fbaf57_745d_460f_8270_3378c2945e30'

        self.mock_src_client = mock.Mock()
        self.mock_dest_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[self.mock_dest_client,
                                                self.mock_src_client]))
        self.mock_object(self.dm_session, 'get_client_and_vserver_name',
                         mock.Mock(side_effect=[
                             (self.mock_src_client, self.source_vserver),
                             (self.mock_dest_client, self.dest_vserver)]))

    def test_get_client_and_vserver_name(self):
        dm_session = data_motion.DataMotionSession()
        client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=client))

        result = dm_session.get_client_and_vserver_name(fake.SHARE_SERVER)
        expected = (client,
                    fake.SHARE_SERVER['backend_details']['vserver_name'])

        self.assertEqual(expected, result)
        data_motion.get_client_for_backend.assert_called_once_with(
            fake.BACKEND_NAME, vserver_name=fake.VSERVER1
        )

    @ddt.data(True, False)
    def test_create_snapmirror_mount(self, mount):
        mock_dest_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=mock_dest_client))
        self.mock_object(self.dm_session, 'wait_for_mount_replica')
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_mount_replica_timeout = 30
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        self.dm_session.create_snapmirror(self.fake_src_share,
                                          self.fake_dest_share,
                                          'data_protection', mount=mount)

        mock_dest_client.create_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, 'data_protection', schedule='hourly'
        )
        mock_dest_client.initialize_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        if mount:
            self.dm_session.wait_for_mount_replica.assert_called_once_with(
                mock_dest_client, self.fake_dest_vol_name, timeout=30)
        else:
            self.dm_session.wait_for_mount_replica.assert_not_called()

    def test_create_snapmirror_svm(self):
        mock_dest_client = mock.Mock()
        self.mock_object(self.dm_session, 'get_client_and_vserver_name',
                         mock.Mock(return_value=(mock_dest_client,
                                                 self.dest_vserver)))
        self.mock_object(self.dm_session, 'get_vserver_from_share_server',
                         mock.Mock(return_value=self.source_vserver))
        policy_name = 'policy_' + self.dest_vserver
        get_snapmirro_policy_name = self.mock_object(
            self.dm_session, '_get_backend_snapmirror_policy_name_svm',
            mock.Mock(return_value=policy_name))

        self.dm_session.create_snapmirror_svm(self.fake_src_share_server,
                                              self.fake_dest_share_server)

        self.dm_session.get_client_and_vserver_name.assert_called_once_with(
            self.fake_dest_share_server
        )
        self.dm_session.get_vserver_from_share_server.assert_called_once_with(
            self.fake_src_share_server
        )
        get_snapmirro_policy_name.assert_called_once_with(
            self.fake_dest_share_server['id'], self.dest_backend_name
        )
        mock_dest_client.create_snapmirror_policy.assert_called_once_with(
            policy_name
        )
        mock_dest_client.create_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver,
            policy=policy_name, schedule='hourly'
        )
        mock_dest_client.initialize_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver
        )

    def test_delete_snapmirror(self):
        mock_src_client = mock.Mock()
        mock_dest_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                mock_src_client]))
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_snapmirror_release_timeout = 30
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))
        mock_wait_for_snapmirror_release_vol = self.mock_object(
            self.dm_session, 'wait_for_snapmirror_release_vol')

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        mock_dest_client.abort_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        mock_wait_for_snapmirror_release_vol.assert_called_once_with(
            self.source_vserver, self.dest_vserver, self.fake_src_vol_name,
            self.fake_dest_vol_name, False, mock_src_client,
            timeout=30
        )

    @ddt.data(True, False)
    def test_delete_snapmirror_svm(self, call_release):
        self.mock_object(self.dm_session, 'wait_for_snapmirror_release_svm')
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_snapmirror_release_timeout = 30
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        self.dm_session.delete_snapmirror_svm(self.fake_src_share_server,
                                              self.fake_dest_share_server,
                                              release=call_release)

        self.mock_dest_client.abort_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver
        )
        self.mock_dest_client.delete_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver
        )
        if call_release:
            release_mock = self.dm_session.wait_for_snapmirror_release_svm
            release_mock.assert_called_once_with(
                self.source_vserver, self.dest_vserver, self.mock_src_client,
                timeout=mock_backend_config.netapp_snapmirror_release_timeout
            )

    def test_delete_snapmirror_does_not_exist(self):
        """Ensure delete succeeds when the snapmirror does not exist."""
        mock_src_client = mock.Mock()
        mock_dest_client = mock.Mock()
        mock_dest_client.abort_snapmirror_vol.side_effect = (
            netapp_api.NaApiError(code=netapp_api.EAPIERROR))
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                mock_src_client]))
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_snapmirror_release_timeout = 30
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))
        mock_wait_for_snapmirror_release_vol = self.mock_object(
            self.dm_session, 'wait_for_snapmirror_release_vol')

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        mock_dest_client.abort_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        mock_wait_for_snapmirror_release_vol.assert_called_once_with(
            self.source_vserver, self.dest_vserver, self.fake_src_vol_name,
            self.fake_dest_vol_name, False, mock_src_client,
            timeout=30
        )

    def test_delete_snapmirror_svm_does_not_exist(self):
        """Ensure delete succeeds when the snapmirror does not exist."""
        self.mock_dest_client.abort_snapmirror_svm.side_effect = (
            netapp_api.NaApiError(code=netapp_api.EAPIERROR))
        self.mock_object(self.dm_session, 'wait_for_snapmirror_release_svm')
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_snapmirror_release_timeout = 30
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        self.dm_session.delete_snapmirror_svm(self.fake_src_share_server,
                                              self.fake_dest_share_server)

        self.mock_dest_client.abort_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver
        )
        self.mock_dest_client.delete_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver
        )
        release_mock = self.dm_session.wait_for_snapmirror_release_svm
        release_mock.assert_called_once_with(
            self.source_vserver, self.dest_vserver, self.mock_src_client,
            timeout=mock_backend_config.netapp_snapmirror_release_timeout
        )

    def test_delete_snapmirror_error_deleting(self):
        """Ensure delete succeeds when the snapmirror does not exist."""
        mock_src_client = mock.Mock()
        mock_dest_client = mock.Mock()
        mock_dest_client.delete_snapmirror_vol.side_effect = (
            netapp_api.NaApiError(code=netapp_api.ESOURCE_IS_DIFFERENT))
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                mock_src_client]))
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_snapmirror_release_timeout = 30
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))
        mock_wait_for_snapmirror_release_vol = self.mock_object(
            self.dm_session, 'wait_for_snapmirror_release_vol')

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        mock_dest_client.abort_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        mock_wait_for_snapmirror_release_vol.assert_called_once_with(
            self.source_vserver, self.dest_vserver, self.fake_src_vol_name,
            self.fake_dest_vol_name, False, mock_src_client,
            timeout=30
        )

    def test_delete_snapmirror_svm_error_deleting(self):
        """Ensure delete succeeds when the snapmirror does not exist."""
        self.mock_dest_client.delete_snapmirror_svm.side_effect = (
            netapp_api.NaApiError(code=netapp_api.ESOURCE_IS_DIFFERENT))
        self.mock_object(self.dm_session, 'wait_for_snapmirror_release_svm')
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_snapmirror_release_timeout = 30
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        self.dm_session.delete_snapmirror_svm(self.fake_src_share_server,
                                              self.fake_dest_share_server)

        self.mock_dest_client.abort_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver
        )
        self.mock_dest_client.delete_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver
        )
        release_mock = self.dm_session.wait_for_snapmirror_release_svm
        release_mock.assert_called_once_with(
            self.source_vserver, self.dest_vserver, self.mock_src_client,
            timeout=mock_backend_config.netapp_snapmirror_release_timeout
        )

    def test_delete_snapmirror_without_release(self):
        mock_src_client = mock.Mock()
        mock_dest_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                mock_src_client]))
        mock_wait_for_snapmirror_release_vol = self.mock_object(
            self.dm_session, 'wait_for_snapmirror_release_vol')

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share,
                                          release=False)

        mock_dest_client.abort_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        self.assertFalse(mock_wait_for_snapmirror_release_vol.called)

    def test_delete_snapmirror_source_unreachable(self):
        mock_dest_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                Exception]))
        mock_wait_for_snapmirror_release_vol = self.mock_object(
            self.dm_session, 'wait_for_snapmirror_release_vol')

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        mock_dest_client.abort_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror_vol.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        self.assertFalse(mock_wait_for_snapmirror_release_vol.called)

    def test_break_snapmirror(self):
        self.mock_object(self.dm_session, 'quiesce_then_abort')

        self.dm_session.break_snapmirror(self.fake_src_share,
                                         self.fake_dest_share)

        self.mock_dest_client.break_snapmirror_vol.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

        self.dm_session.quiesce_then_abort.assert_called_once_with(
            self.fake_src_share, self.fake_dest_share,
            quiesce_wait_time=None)

        self.mock_dest_client.mount_volume.assert_called_once_with(
            self.fake_dest_vol_name)

    def test_break_snapmirror_no_mount(self):
        self.mock_object(self.dm_session, 'quiesce_then_abort')

        self.dm_session.break_snapmirror(self.fake_src_share,
                                         self.fake_dest_share,
                                         mount=False)

        self.mock_dest_client.break_snapmirror_vol.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

        self.dm_session.quiesce_then_abort.assert_called_once_with(
            self.fake_src_share, self.fake_dest_share,
            quiesce_wait_time=None)

        self.assertFalse(self.mock_dest_client.mount_volume.called)

    def test_break_snapmirror_wait_for_quiesced(self):
        self.mock_object(self.dm_session, 'quiesce_then_abort')

        self.dm_session.break_snapmirror(self.fake_src_share,
                                         self.fake_dest_share)

        self.dm_session.quiesce_then_abort.assert_called_once_with(
            self.fake_src_share, self.fake_dest_share,
            quiesce_wait_time=None)

        self.mock_dest_client.break_snapmirror_vol.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

        self.mock_dest_client.mount_volume.assert_called_once_with(
            self.fake_dest_vol_name)

    @ddt.data(None, 2, 30)
    def test_quiesce_then_abort_wait_time(self, wait_time):
        self.mock_object(time, 'sleep')
        mock_get_snapmirrors = mock.Mock(
            return_value=[{'relationship-status': "transferring"}])
        self.mock_object(self.mock_dest_client, 'get_snapmirrors',
                         mock_get_snapmirrors)
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_snapmirror_quiesce_timeout = 10
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        self.dm_session.quiesce_then_abort(self.fake_src_share,
                                           self.fake_dest_share,
                                           quiesce_wait_time=wait_time)

        self.mock_dest_client.get_snapmirrors.assert_called_with(
            source_vserver=self.source_vserver,
            dest_vserver=self.dest_vserver,
            source_volume=self.fake_src_vol_name,
            dest_volume=self.fake_dest_vol_name,
            desired_attributes=['relationship-status', 'mirror-state']
        )

        call_count = self.mock_dest_client.get_snapmirrors.call_count
        if wait_time:
            if wait_time > 5:
                self.assertEqual(wait_time / 5, call_count)
            else:
                self.assertEqual(1, call_count)
        else:
            self.assertEqual(2, call_count)

    def test_quiesce_then_abort_timeout(self):
        self.mock_object(time, 'sleep')
        mock_get_snapmirrors = mock.Mock(
            return_value=[{'relationship-status': "transferring"}])
        self.mock_object(self.mock_dest_client, 'get_snapmirrors',
                         mock_get_snapmirrors)
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_snapmirror_quiesce_timeout = 10
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        self.dm_session.quiesce_then_abort(self.fake_src_share,
                                           self.fake_dest_share)

        self.mock_dest_client.get_snapmirrors.assert_called_with(
            source_vserver=self.source_vserver,
            dest_vserver=self.dest_vserver,
            source_volume=self.fake_src_vol_name,
            dest_volume=self.fake_dest_vol_name,
            desired_attributes=['relationship-status', 'mirror-state']
        )
        self.assertEqual(2, self.mock_dest_client.get_snapmirrors.call_count)

        self.mock_dest_client.quiesce_snapmirror_vol.assert_called_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

        self.mock_dest_client.abort_snapmirror_vol.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name,
            clear_checkpoint=False
        )

    def test_quiesce_then_abort_svm_timeout(self):
        self.mock_object(time, 'sleep')
        mock_get_snapmirrors = mock.Mock(
            return_value=[{'relationship-status': "transferring"}])
        self.mock_object(self.mock_dest_client, 'get_snapmirrors_svm',
                         mock_get_snapmirrors)
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_snapmirror_quiesce_timeout = 10
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        self.dm_session.quiesce_then_abort_svm(self.fake_src_share_server,
                                               self.fake_dest_share_server)

        self.mock_dest_client.get_snapmirrors_svm.assert_called_with(
            source_vserver=self.source_vserver,
            dest_vserver=self.dest_vserver,
            desired_attributes=['relationship-status', 'mirror-state']
        )
        self.assertEqual(2,
                         self.mock_dest_client.get_snapmirrors_svm.call_count)

        self.mock_dest_client.quiesce_snapmirror_svm.assert_called_with(
            self.source_vserver, self.dest_vserver)

        self.mock_dest_client.abort_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver,
            clear_checkpoint=False
        )

    def test_quiesce_then_abort_wait_for_quiesced(self):
        self.mock_object(time, 'sleep')
        self.mock_object(self.mock_dest_client, 'get_snapmirrors',
                         mock.Mock(side_effect=[
                             [{'relationship-status': "transferring"}],
                             [{'relationship-status': "quiesced"}]]))

        self.dm_session.quiesce_then_abort(self.fake_src_share,
                                           self.fake_dest_share)

        self.mock_dest_client.get_snapmirrors.assert_called_with(
            source_vserver=self.source_vserver,
            dest_vserver=self.dest_vserver,
            source_volume=self.fake_src_vol_name,
            dest_volume=self.fake_dest_vol_name,
            desired_attributes=['relationship-status', 'mirror-state']
        )
        self.assertEqual(2, self.mock_dest_client.get_snapmirrors.call_count)

        self.mock_dest_client.quiesce_snapmirror_vol.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

    def test_quiesce_then_abort_svm_wait_for_quiesced(self):
        self.mock_object(time, 'sleep')
        self.mock_object(self.mock_dest_client, 'get_snapmirrors_svm',
                         mock.Mock(side_effect=[
                             [{'relationship-status': "transferring"}],
                             [{'relationship-status': "quiesced"}]]))

        self.dm_session.quiesce_then_abort_svm(self.fake_src_share_server,
                                               self.fake_dest_share_server)

        self.mock_dest_client.get_snapmirrors_svm.assert_called_with(
            source_vserver=self.source_vserver,
            dest_vserver=self.dest_vserver,
            desired_attributes=['relationship-status', 'mirror-state']
        )
        self.assertEqual(2,
                         self.mock_dest_client.get_snapmirrors_svm.call_count)

        self.mock_dest_client.quiesce_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver)

    def test_resync_snapmirror(self):
        self.dm_session.resync_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        self.mock_dest_client.resync_snapmirror_vol.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

    def test_change_snapmirror_source(self):
        fake_new_src_share = copy.deepcopy(fake.SHARE)
        fake_new_src_share['id'] = 'd02d497a-236c-4852-812a-0d39373e312a'
        fake_new_src_share_name = 'share_d02d497a_236c_4852_812a_0d39373e312a'
        mock_new_src_client = mock.Mock()
        self.mock_object(self.dm_session, 'delete_snapmirror')
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[self.mock_dest_client,
                                                self.mock_src_client,
                                                self.mock_dest_client,
                                                mock_new_src_client]))
        self.mock_object(na_utils, 'get_relationship_type',
                         mock.Mock(return_value=na_utils.DATA_PROTECTION_TYPE))

        self.dm_session.change_snapmirror_source(
            self.fake_dest_share, self.fake_src_share, fake_new_src_share,
            [self.fake_dest_share, self.fake_src_share, fake_new_src_share])

        self.assertFalse(self.mock_src_client.release_snapmirror_vol.called)

        self.assertEqual(4, self.dm_session.delete_snapmirror.call_count)
        self.dm_session.delete_snapmirror.assert_called_with(
            mock.ANY, mock.ANY, release=False, relationship_info_only=False
        )

        na_utils.get_relationship_type.assert_called_once_with(False)
        self.mock_dest_client.create_snapmirror_vol.assert_called_once_with(
            mock.ANY, fake_new_src_share_name, mock.ANY,
            self.fake_dest_vol_name, na_utils.DATA_PROTECTION_TYPE,
            schedule='hourly'
        )

        self.mock_dest_client.resync_snapmirror_vol.assert_called_once_with(
            mock.ANY, fake_new_src_share_name, mock.ANY,
            self.fake_dest_vol_name
        )

    def test_change_snapmirror_source_dhss_true(self):
        fake_new_src_share = copy.deepcopy(self.fake_src_share)
        fake_new_src_share['id'] = 'd02d497a-236c-4852-812a-0d39373e312a'
        fake_new_src_share_name = 'share_d02d497a_236c_4852_812a_0d39373e312a'
        fake_new_src_share_server = fake_new_src_share['share_server']
        fake_new_src_ss_name = (
            fake_new_src_share_server['backend_details']['vserver_name'])
        self.mock_object(self.dm_session, 'delete_snapmirror')
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[self.mock_dest_client,
                                                self.mock_src_client]))
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.driver_handles_share_servers = True
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))
        self.mock_object(self.mock_dest_client, 'get_vserver_peers',
                         mock.Mock(return_value=[]))
        peer_cluster_name = 'new_src_cluster_name'
        self.mock_object(self.mock_src_client, 'get_cluster_name',
                         mock.Mock(return_value=peer_cluster_name))
        self.mock_object(na_utils, 'get_relationship_type',
                         mock.Mock(return_value=na_utils.DATA_PROTECTION_TYPE))

        self.dm_session.change_snapmirror_source(
            self.fake_dest_share, self.fake_src_share, fake_new_src_share,
            [self.fake_dest_share, self.fake_src_share, fake_new_src_share])

        self.assertEqual(4, self.dm_session.delete_snapmirror.call_count)

        self.mock_dest_client.get_vserver_peers.assert_called_once_with(
            self.dest_vserver, fake_new_src_ss_name
        )
        self.assertTrue(self.mock_src_client.get_cluster_name.called)
        self.mock_dest_client.create_vserver_peer.assert_called_once_with(
            self.dest_vserver, fake_new_src_ss_name,
            peer_cluster_name=peer_cluster_name
        )
        self.mock_src_client.accept_vserver_peer.assert_called_once_with(
            fake_new_src_ss_name, self.dest_vserver
        )
        na_utils.get_relationship_type.assert_called_once_with(False)
        self.dm_session.delete_snapmirror.assert_called_with(
            mock.ANY, mock.ANY, release=False, relationship_info_only=False
        )
        self.mock_dest_client.create_snapmirror_vol.assert_called_once_with(
            mock.ANY, fake_new_src_share_name, mock.ANY,
            self.fake_dest_vol_name, na_utils.DATA_PROTECTION_TYPE,
            schedule='hourly'
        )
        self.mock_dest_client.resync_snapmirror_vol.assert_called_once_with(
            mock.ANY, fake_new_src_share_name, mock.ANY,
            self.fake_dest_vol_name
        )

    def test_get_snapmirrors(self):
        self.mock_object(self.mock_dest_client, 'get_snapmirrors')

        self.dm_session.get_snapmirrors(self.fake_src_share,
                                        self.fake_dest_share)

        self.mock_dest_client.get_snapmirrors.assert_called_with(
            source_vserver=self.source_vserver,
            dest_vserver=self.dest_vserver,
            source_volume=self.fake_src_vol_name,
            dest_volume=self.fake_dest_vol_name,
            desired_attributes=['relationship-status',
                                'mirror-state',
                                'schedule',
                                'source-vserver',
                                'source-volume',
                                'last-transfer-end-timestamp',
                                'last-transfer-size',
                                'last-transfer-error']
        )
        self.assertEqual(1, self.mock_dest_client.get_snapmirrors.call_count)

    def test_get_snapmirrors_svm(self):
        mock_dest_client = mock.Mock()
        self.mock_object(self.dm_session, 'get_client_and_vserver_name',
                         mock.Mock(return_value=(mock_dest_client,
                                                 self.dest_vserver)))
        self.mock_object(mock_dest_client, 'get_snapmirrors_svm')

        self.dm_session.get_snapmirrors_svm(self.fake_src_share_server,
                                            self.fake_dest_share_server)

        mock_dest_client.get_snapmirrors_svm.assert_called_with(
            source_vserver=self.source_vserver,
            dest_vserver=self.dest_vserver,
            desired_attributes=['relationship-status',
                                'mirror-state',
                                'last-transfer-end-timestamp']
        )
        self.assertEqual(1, mock_dest_client.get_snapmirrors_svm.call_count)

    def test_get_snapmirror_destinations_svm(self):
        mock_dest_client = mock.Mock()
        self.mock_object(self.dm_session, 'get_client_and_vserver_name',
                         mock.Mock(return_value=(mock_dest_client,
                                                 self.dest_vserver)))
        self.mock_object(mock_dest_client, 'get_snapmirror_destinations_svm')

        self.dm_session.get_snapmirror_destinations_svm(
            self.fake_src_share_server, self.fake_dest_share_server)

        mock_dest_client.get_snapmirror_destinations_svm.assert_called_with(
            source_vserver=self.source_vserver,
            dest_vserver=self.dest_vserver,
        )
        self.assertEqual(1, mock_dest_client.get_snapmirror_destinations_svm
                         .call_count)

    def test_update_snapmirror(self):
        self.mock_object(self.mock_dest_client, 'get_snapmirrors')

        self.dm_session.update_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        self.mock_dest_client.update_snapmirror_vol.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

    def test_update_snapmirror_svm(self):
        mock_dest_client = mock.Mock()
        self.mock_object(self.dm_session, 'get_client_and_vserver_name',
                         mock.Mock(return_value=(mock_dest_client,
                                                 self.dest_vserver)))

        self.dm_session.update_snapmirror_svm(self.fake_src_share_server,
                                              self.fake_dest_share_server)

        mock_dest_client.update_snapmirror_svm.assert_called_once_with(
            self.source_vserver, self.dest_vserver)

    def test_abort_and_break_snapmirror_svm(self):
        mock_dest_client = mock.Mock()
        self.mock_object(self.dm_session, 'get_client_and_vserver_name',
                         mock.Mock(return_value=(mock_dest_client,
                                                 self.dest_vserver)))
        self.mock_object(self.dm_session, 'quiesce_then_abort_svm')

        self.dm_session.quiesce_and_break_snapmirror_svm(
            self.fake_src_share_server, self.fake_dest_share_server
        )

        self.dm_session.get_client_and_vserver_name.assert_called_once_with(
            self.fake_dest_share_server
        )
        self.dm_session.quiesce_then_abort_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        mock_dest_client.break_snapmirror_svm(self.source_vserver,
                                              self.dest_vserver)

    @ddt.data({'snapmirrors': ['fake_snapmirror'],
               'vserver_subtype': 'default'},
              {'snapmirrors': [],
               'vserver_subtype': 'default'},
              {'snapmirrors': [],
               'vserver_subtype': 'dp_destination'})
    @ddt.unpack
    def test_cancel_snapmirror_svm(self, snapmirrors, vserver_subtype):
        mock_dest_client = mock.Mock()
        self.mock_object(self.dm_session, 'get_client_and_vserver_name',
                         mock.Mock(return_value=(mock_dest_client,
                                                 self.dest_vserver)))
        mock_backend_config = na_fakes.create_configuration()
        mock_backend_config.netapp_server_migration_state_change_timeout = 30
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))
        self.mock_object(self.dm_session, 'get_snapmirrors_svm',
                         mock.Mock(return_value=snapmirrors))
        self.mock_object(self.dm_session, 'quiesce_and_break_snapmirror_svm')
        self.mock_object(self.dm_session, 'wait_for_vserver_state')
        self.mock_object(self.dm_session, 'delete_snapmirror_svm')
        vserver_info = copy.deepcopy(fake.VSERVER_INFO)
        vserver_info['subtype'] = vserver_subtype
        self.mock_object(mock_dest_client, 'get_vserver_info',
                         mock.Mock(return_value=vserver_info))
        self.mock_object(self.dm_session, 'convert_svm_to_default_subtype')

        self.dm_session.cancel_snapmirror_svm(self.fake_src_share_server,
                                              self.fake_dest_share_server)

        data_motion.get_backend_configuration.assert_called_once_with(
            self.dest_backend_name
        )
        self.dm_session.get_client_and_vserver_name.assert_called_once_with(
            self.fake_dest_share_server
        )
        self.dm_session.get_snapmirrors_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        if snapmirrors:
            quiesce_mock = self.dm_session.quiesce_and_break_snapmirror_svm
            quiesce_mock.assert_called_once_with(
                self.fake_src_share_server, self.fake_dest_share_server
            )
            self.dm_session.wait_for_vserver_state.assert_called_once_with(
                self.dest_vserver, mock_dest_client, subtype='default',
                state='running', operational_state='stopped',
                timeout=(mock_backend_config
                         .netapp_server_migration_state_change_timeout)
            )
            self.dm_session.delete_snapmirror_svm.assert_called_once_with(
                self.fake_src_share_server, self.fake_dest_share_server
            )
        else:
            mock_dest_client.get_vserver_info.assert_called_once_with(
                self.dest_vserver
            )
            convert_svm = self.dm_session.convert_svm_to_default_subtype
            if vserver_subtype == 'dp_destination':
                convert_svm.assert_called_once_with(
                    self.dest_vserver, mock_dest_client,
                    timeout=(mock_backend_config
                             .netapp_server_migration_state_change_timeout)
                )
            else:
                self.assertFalse(convert_svm.called)

    def test_resume_snapmirror(self):
        self.mock_object(self.mock_dest_client, 'get_snapmirrors')

        self.dm_session.resume_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        self.mock_dest_client.resume_snapmirror_vol.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

    @ddt.data((None, exception.StorageCommunicationException),
              (exception.StorageCommunicationException, None))
    @ddt.unpack
    def test_remove_qos_on_old_active_replica_unreachable_backend(self,
                                                                  side_eff_1,
                                                                  side_eff_2):
        mock_source_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=mock_source_client))
        self.mock_object(
            mock_source_client, 'set_qos_policy_group_for_volume',
            mock.Mock(side_effect=side_eff_1))
        self.mock_object(
            mock_source_client, 'mark_qos_policy_group_for_deletion',
            mock.Mock(side_effect=side_eff_2))
        self.mock_object(data_motion.LOG, 'exception')

        retval = self.dm_session.remove_qos_on_old_active_replica(
            self.fake_src_share)

        self.assertIsNone(retval)
        (mock_source_client.set_qos_policy_group_for_volume
         .assert_called_once_with(self.fake_src_vol_name, 'none'))
        data_motion.LOG.exception.assert_called_once()

    def test_remove_qos_on_old_active_replica(self):
        mock_source_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=mock_source_client))
        self.mock_object(data_motion.LOG, 'exception')

        retval = self.dm_session.remove_qos_on_old_active_replica(
            self.fake_src_share)

        self.assertIsNone(retval)
        (mock_source_client.set_qos_policy_group_for_volume
         .assert_called_once_with(self.fake_src_vol_name, 'none'))
        data_motion.LOG.exception.assert_not_called()

    @ddt.data(True, False)
    def test_convert_svm_to_default_subtype(self, is_dest):
        mock_client = mock.Mock()
        vserver_info_default = copy.deepcopy(fake.VSERVER_INFO)
        vserver_info_default['subtype'] = 'default'
        vserver_info_dp = copy.deepcopy(fake.VSERVER_INFO)
        vserver_info_dp['subtype'] = 'dp_destination'
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(side_effect=[vserver_info_dp,
                                                vserver_info_default]))
        self.mock_object(mock_client, 'break_snapmirror_svm')

        self.dm_session.convert_svm_to_default_subtype(fake.VSERVER1,
                                                       mock_client,
                                                       is_dest_path=is_dest,
                                                       timeout=20)

        mock_client.get_vserver_info.assert_has_calls([
            mock.call(fake.VSERVER1), mock.call(fake.VSERVER1)])
        if is_dest:
            mock_client.break_snapmirror_svm.assert_called_once_with(
                dest_vserver=fake.VSERVER1
            )
        else:
            mock_client.break_snapmirror_svm.assert_called_once_with(
                source_vserver=fake.VSERVER1
            )

    def test_convert_svm_to_default_subtype_timeout(self):
        mock_client = mock.Mock()
        vserver_info_dp = copy.deepcopy(fake.VSERVER_INFO)
        vserver_info_dp['subtype'] = 'dp_destination'
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(side_effect=[vserver_info_dp]))
        self.mock_object(mock_client, 'break_snapmirror_svm')

        self.assertRaises(
            exception.NetAppException,
            self.dm_session.convert_svm_to_default_subtype,
            fake.VSERVER1, mock_client, is_dest_path=True, timeout=10)

        mock_client.get_vserver_info.assert_called_once_with(fake.VSERVER1)
        mock_client.break_snapmirror_svm.assert_called_once_with(
            dest_vserver=fake.VSERVER1)

    def test_wait_for_vserver_state(self,):
        mock_client = mock.Mock()
        vserver_info_default = copy.deepcopy(fake.VSERVER_INFO)
        vserver_info_default['subtype'] = 'default'
        vserver_info_dp = copy.deepcopy(fake.VSERVER_INFO)
        vserver_info_dp['subtype'] = 'dp_destination'
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(side_effect=[vserver_info_dp,
                                                vserver_info_default]))

        self.dm_session.wait_for_vserver_state(fake.VSERVER1, mock_client,
                                               state='running',
                                               operational_state='running',
                                               subtype='default', timeout=20)

        mock_client.get_vserver_info.assert_has_calls([
            mock.call(fake.VSERVER1), mock.call(fake.VSERVER1)])

    def test_wait_for_vserver_state_timeout(self):
        mock_client = mock.Mock()
        vserver_info_dp = copy.deepcopy(fake.VSERVER_INFO)
        vserver_info_dp['subtype'] = 'dp_destination'
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(side_effect=[vserver_info_dp]))

        self.assertRaises(
            exception.NetAppException,
            self.dm_session.wait_for_vserver_state,
            fake.VSERVER1, mock_client, state='running',
            operational_state='running', subtype='default', timeout=10)

        mock_client.get_vserver_info.assert_called_once_with(fake.VSERVER1)

    @ddt.data(mock.Mock(),
              mock.Mock(side_effect=netapp_api.NaApiError(
                  code=netapp_api.EOBJECTNOTFOUND)))
    def test_wait_for_snapmirror_release_svm(self, release_snapmirror_ret):
        src_mock_client = mock.Mock()
        get_snapmirrors_mock = self.mock_object(
            src_mock_client, 'get_snapmirror_destinations_svm',
            mock.Mock(side_effect=[['fake_snapmirror'], []]))
        self.mock_object(src_mock_client, 'release_snapmirror_svm',
                         release_snapmirror_ret)

        self.dm_session.wait_for_snapmirror_release_svm(fake.VSERVER1,
                                                        fake.VSERVER2,
                                                        src_mock_client,
                                                        timeout=20)
        get_snapmirrors_mock.assert_has_calls([
            mock.call(source_vserver=fake.VSERVER1,
                      dest_vserver=fake.VSERVER2),
            mock.call(source_vserver=fake.VSERVER1,
                      dest_vserver=fake.VSERVER2)])
        src_mock_client.release_snapmirror_svm.assert_called_once_with(
            fake.VSERVER1, fake.VSERVER2)

    def test_wait_for_snapmirror_release_svm_timeout(self):
        src_mock_client = mock.Mock()
        get_snapmirrors_mock = self.mock_object(
            src_mock_client, 'get_snapmirror_destinations_svm',
            mock.Mock(side_effect=[['fake_snapmirror']]))
        self.mock_object(src_mock_client, 'release_snapmirror_svm')

        self.assertRaises(exception.NetAppException,
                          self.dm_session.wait_for_snapmirror_release_svm,
                          fake.VSERVER1, fake.VSERVER2,
                          src_mock_client, timeout=10)

        get_snapmirrors_mock.assert_called_once_with(
            source_vserver=fake.VSERVER1, dest_vserver=fake.VSERVER2)
        src_mock_client.release_snapmirror_svm.assert_called_once_with(
            fake.VSERVER1, fake.VSERVER2
        )

    def test_wait_for_mount_replica(self):

        mock_client = mock.Mock()
        self.mock_object(time, 'sleep')
        mock_warning_log = self.mock_object(data_motion.LOG, 'warning')

        self.dm_session.wait_for_mount_replica(
            mock_client, fake.SHARE_NAME)

        mock_client.mount_volume.ssert_called_once_with(fake.SHARE_NAME)
        self.assertEqual(0, mock_warning_log.call_count)

    def test_wait_for_mount_replica_timeout(self):

        mock_client = mock.Mock()
        self.mock_object(time, 'sleep')
        mock_warning_log = self.mock_object(data_motion.LOG, 'warning')
        undergoing_snapmirror = (
            'The volume is undergoing a snapmirror initialize.')
        na_api_error = netapp_api.NaApiError(code=netapp_api.EAPIERROR,
                                             message=undergoing_snapmirror)
        mock_client.mount_volume.side_effect = na_api_error

        self.assertRaises(exception.NetAppException,
                          self.dm_session.wait_for_mount_replica,
                          mock_client, fake.SHARE_NAME, timeout=30)

        self.assertEqual(3, mock_client.mount_volume.call_count)
        self.assertEqual(3, mock_warning_log.call_count)

    def test_wait_for_mount_replica_api_not_found(self):

        mock_client = mock.Mock()
        self.mock_object(time, 'sleep')
        mock_warning_log = self.mock_object(data_motion.LOG, 'warning')
        na_api_error = netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND)
        mock_client.mount_volume.side_effect = na_api_error

        self.assertRaises(exception.NetAppException,
                          self.dm_session.wait_for_mount_replica,
                          mock_client, fake.SHARE_NAME, timeout=30)

        mock_client.mount_volume.assert_called_once_with(fake.SHARE_NAME)
        mock_warning_log.assert_not_called()

    @ddt.data(mock.Mock(),
              mock.Mock(side_effect=netapp_api.NaApiError(
                  code=netapp_api.EOBJECTNOTFOUND)))
    def test_wait_for_snapmirror_release_vol(self, release_snapmirror_ret):
        src_mock_client = mock.Mock()
        get_snapmirrors_mock = self.mock_object(
            src_mock_client, 'get_snapmirror_destinations',
            mock.Mock(side_effect=[['fake_snapmirror'], []]))
        self.mock_object(src_mock_client, 'release_snapmirror_vol',
                         release_snapmirror_ret)

        self.dm_session.wait_for_snapmirror_release_vol(fake.VSERVER1,
                                                        fake.VSERVER2,
                                                        fake.SHARE_NAME,
                                                        fake.SHARE_NAME2,
                                                        False,
                                                        src_mock_client,
                                                        timeout=20)
        get_snapmirrors_mock.assert_has_calls([
            mock.call(source_vserver=fake.VSERVER1,
                      dest_vserver=fake.VSERVER2,
                      source_volume=fake.SHARE_NAME,
                      dest_volume=fake.SHARE_NAME2),
            mock.call(source_vserver=fake.VSERVER1,
                      dest_vserver=fake.VSERVER2,
                      source_volume=fake.SHARE_NAME,
                      dest_volume=fake.SHARE_NAME2)])
        src_mock_client.release_snapmirror_vol.assert_called_once_with(
            fake.VSERVER1, fake.SHARE_NAME, fake.VSERVER2, fake.SHARE_NAME2,
            relationship_info_only=False)

    def test_wait_for_snapmirror_release_vol_timeout(self):
        src_mock_client = mock.Mock()
        get_snapmirrors_mock = self.mock_object(
            src_mock_client, 'get_snapmirror_destinations',
            mock.Mock(side_effect=[['fake_snapmirror']]))
        self.mock_object(src_mock_client, 'release_snapmirror_vol')

        self.assertRaises(exception.NetAppException,
                          self.dm_session.wait_for_snapmirror_release_vol,
                          fake.VSERVER1, fake.VSERVER2, fake.SHARE_NAME,
                          fake.SHARE_NAME2, False, src_mock_client,
                          timeout=10)

        get_snapmirrors_mock.assert_has_calls([
            mock.call(source_vserver=fake.VSERVER1,
                      dest_vserver=fake.VSERVER2,
                      source_volume=fake.SHARE_NAME,
                      dest_volume=fake.SHARE_NAME2)])
        src_mock_client.release_snapmirror_vol.assert_called_once_with(
            fake.VSERVER1, fake.SHARE_NAME, fake.VSERVER2, fake.SHARE_NAME2,
            relationship_info_only=False)

    @ddt.data([{'id': 'src_share'}, {'id': 'dst_share'}],
              [{'id': 'dst_share'}])
    def test_cleanup_previous_snapmirror_relationships(self, replica_list):
        mock_src_client = mock.Mock()
        src_backend_info = ('src_share', 'src_vserver', 'src_backend')
        dst_backend_info = ('dst_share', 'dst_vserver', 'dst_backend')
        self.mock_object(self.dm_session, 'get_backend_info_for_share',
                         mock.Mock(side_effect=[src_backend_info,
                                                dst_backend_info]))
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=mock_src_client))
        self.mock_object(mock_src_client, 'release_snapmirror_vol')

        result = self.dm_session.cleanup_previous_snapmirror_relationships(
            {'id': 'src_share'}, replica_list)

        data_motion.get_client_for_backend.assert_called_once_with(
            'src_backend', vserver_name='src_vserver')
        self.dm_session.get_backend_info_for_share.assert_has_calls([
            mock.call({'id': 'src_share'}),
            mock.call({'id': 'dst_share'})
        ])
        mock_src_client.release_snapmirror_vol.assert_called_once_with(
            'src_vserver', 'src_share', 'dst_vserver', 'dst_share')

        self.assertIsNone(result)

    @ddt.data(netapp_api.NaApiError(),
              netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND),
              netapp_api.NaApiError(code=netapp_api.ESOURCE_IS_DIFFERENT),
              netapp_api.NaApiError(code='some_random_code',
                                    message="(entry doesn't exist)"),
              netapp_api.NaApiError(code='some_random_code',
                                    message='(actually, entry does exist!)'))
    def test_cleanup_previous_snapmirror_relationships_does_not_exist(
            self, release_exception):
        mock_src_client = mock.Mock()
        self.mock_object(self.dm_session, 'get_backend_info_for_share',
                         mock.Mock(return_value=(
                             mock.Mock(), mock.Mock(), mock.Mock())))
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=mock_src_client))
        self.mock_object(mock_src_client, 'release_snapmirror_vol',
                         mock.Mock(side_effect=release_exception))

        replica = {'id': 'src_share'}
        replica_list = [replica, {'id': 'dst_share'}]

        result = self.dm_session.cleanup_previous_snapmirror_relationships(
            replica, replica_list)

        mock_src_client.release_snapmirror_vol.assert_called()
        self.assertIsNone(result)
