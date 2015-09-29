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

import mock
from oslo_config import cfg

from manila.share import configuration
from manila.share import driver
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.cluster_mode import data_motion
from manila.share.drivers.netapp import options as na_opts
from manila import test
from manila.tests.share.drivers.netapp.dataontap import fakes as fake
from manila.tests.share.drivers.netapp import fakes as na_fakes


CONF = cfg.CONF


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
        self.config.append_config_values(na_opts.netapp_replication_opts)
        CONF.set_override("share_backend_name", self.backend,
                          group=self.backend)
        CONF.set_override("netapp_transport_type", "https",
                          group=self.backend)
        CONF.set_override("netapp_login", "fake_user",
                          group=self.backend)
        CONF.set_override("netapp_password", "fake_password",
                          group=self.backend)
        CONF.set_override("netapp_server_hostname", "fake_hostname",
                          group=self.backend)
        CONF.set_override("netapp_server_port", 8866,
                          group=self.backend)

    def test_get_client_for_backend(self):
        self.mock_object(data_motion, "get_backend_configuration",
                         mock.Mock(return_value=self.config))

        data_motion.get_client_for_backend(self.backend)

        self.mock_cmode_client.assert_called_once_with(
            hostname='fake_hostname', password='fake_password',
            username='fake_user', transport_type='https', port=8866,
            trace=mock.ANY, vserver=None)

    def test_get_client_for_backend_with_vserver(self):
        self.mock_object(data_motion, "get_backend_configuration",
                         mock.Mock(return_value=self.config))

        CONF.set_override("netapp_vserver", 'fake_vserver',
                          group=self.backend)

        data_motion.get_client_for_backend(self.backend)

        self.mock_cmode_client.assert_called_once_with(
            hostname='fake_hostname', password='fake_password',
            username='fake_user', transport_type='https', port=8866,
            trace=mock.ANY, vserver='fake_vserver')

    def test_get_config_for_backend(self):
        self.mock_object(data_motion, "CONF")
        data_motion.CONF.list_all_sections.return_value = [self.backend]

        config = data_motion.get_backend_configuration(self.backend)

        self.assertEqual(self.backend, config.share_backend_name)

    def test_get_config_for_backend_share_backend_name_mismatch(self):
        self.mock_object(data_motion, "CONF")
        configuration.Configuration(driver.share_opts,
                                    config_group='my_happy_stanza')
        self.config.append_config_values(na_opts.netapp_cluster_opts)
        self.config.append_config_values(na_opts.netapp_connection_opts)
        self.config.append_config_values(na_opts.netapp_basicauth_opts)
        self.config.append_config_values(na_opts.netapp_transport_opts)
        self.config.append_config_values(na_opts.netapp_support_opts)
        self.config.append_config_values(na_opts.netapp_provisioning_opts)
        self.config.append_config_values(na_opts.netapp_replication_opts)
        CONF.set_override("share_backend_name", self.backend,
                          group='my_happy_stanza')
        data_motion.CONF.list_all_sections.return_value = ['my_happy_stanza']

        config = data_motion.get_backend_configuration(self.backend)

        self.assertEqual(self.backend, config.share_backend_name)

    def test_get_config_for_backend_not_configured(self):
        self.mock_object(data_motion, "CONF")
        data_motion.CONF.list_all_sections.return_value = []

        config = data_motion.get_backend_configuration(self.backend)

        self.assertIsNone(config)


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
        config.append_config_values(na_opts.netapp_replication_opts)

        self.mock_object(data_motion, "get_backend_configuration",
                         mock.Mock(return_value=config))

        self.mock_cmode_client = self.mock_object(client_cmode,
                                                  "NetAppCmodeClient",
                                                  mock.Mock())
        self.dm_session = data_motion.DataMotionSession()
        self.fake_src_share = copy.deepcopy(fake.SHARE)
        self.fake_src_share_server = copy.deepcopy(fake.SHARE_SERVER)
        self.source_vserver = 'source_vserver'
        self.fake_src_share_server['backend_details']['vserver_name'] = (
            self.source_vserver
        )
        self.fake_src_share['share_server'] = self.fake_src_share_server
        self.fake_src_share['id'] = 'c02d497a-236c-4852-812a-0d39373e312a'
        self.fake_src_vol_name = 'share_c02d497a_236c_4852_812a_0d39373e312a'
        self.fake_dest_share = copy.deepcopy(fake.SHARE)
        self.fake_dest_share_server = copy.deepcopy(fake.SHARE_SERVER)
        self.dest_vserver = 'dest_vserver'
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

    def test_create_snapmirror(self):
        mock_dest_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=mock_dest_client))

        self.dm_session.create_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        mock_dest_client.create_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, schedule='hourly'
        )
        mock_dest_client.initialize_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )

    def test_delete_snapmirror(self):
        mock_src_client = mock.Mock()
        mock_dest_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                mock_src_client]))

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        mock_dest_client.abort_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        mock_src_client.release_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )

    def test_delete_snapmirror_does_not_exist(self):
        """Ensure delete succeeds when the snapmirror does not exist."""
        mock_src_client = mock.Mock()
        mock_dest_client = mock.Mock()
        mock_dest_client.abort_snapmirror.side_effect = netapp_api.NaApiError(
            code=netapp_api.EAPIERROR
        )
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                mock_src_client]))

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        mock_dest_client.abort_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        mock_src_client.release_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )

    def test_delete_snapmirror_error_deleting(self):
        """Ensure delete succeeds when the snapmirror does not exist."""
        mock_src_client = mock.Mock()
        mock_dest_client = mock.Mock()
        mock_dest_client.delete_snapmirror.side_effect = netapp_api.NaApiError(
            code=netapp_api.ESOURCE_IS_DIFFERENT
        )
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                mock_src_client]))

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        mock_dest_client.abort_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        mock_src_client.release_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )

    def test_delete_snapmirror_error_releasing(self):
        """Ensure delete succeeds when the snapmirror does not exist."""
        mock_src_client = mock.Mock()
        mock_dest_client = mock.Mock()
        mock_src_client.release_snapmirror.side_effect = (
            netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND))
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                mock_src_client]))

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        mock_dest_client.abort_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        mock_src_client.release_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )

    def test_delete_snapmirror_without_release(self):
        mock_src_client = mock.Mock()
        mock_dest_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                mock_src_client]))

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share,
                                          release=False)

        mock_dest_client.abort_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )
        self.assertFalse(mock_src_client.release_snapmirror.called)

    def test_delete_snapmirror_source_unreachable(self):
        mock_src_client = mock.Mock()
        mock_dest_client = mock.Mock()
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[mock_dest_client,
                                                Exception]))

        self.dm_session.delete_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        mock_dest_client.abort_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name, clear_checkpoint=False
        )
        mock_dest_client.delete_snapmirror.assert_called_once_with(
            mock.ANY, self.fake_src_vol_name, mock.ANY,
            self.fake_dest_vol_name
        )

        self.assertFalse(mock_src_client.release_snapmirror.called)

    def test_break_snapmirror(self):
        self.mock_object(self.dm_session, 'quiesce_then_abort')

        self.dm_session.break_snapmirror(self.fake_src_share,
                                         self.fake_dest_share)

        self.mock_dest_client.break_snapmirror.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

        self.dm_session.quiesce_then_abort.assert_called_once_with(
            self.fake_src_share, self.fake_dest_share)

        self.mock_dest_client.mount_volume.assert_called_once_with(
            self.fake_dest_vol_name)

    def test_break_snapmirror_wait_for_quiesced(self):
        self.mock_object(self.dm_session, 'quiesce_then_abort')

        self.dm_session.break_snapmirror(self.fake_src_share,
                                         self.fake_dest_share)

        self.dm_session.quiesce_then_abort.assert_called_once_with(
            self.fake_src_share, self.fake_dest_share)

        self.mock_dest_client.break_snapmirror.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

        self.mock_dest_client.mount_volume.assert_called_once_with(
            self.fake_dest_vol_name)

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
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name,
            desired_attributes=['relationship-status', 'mirror-state']
        )
        self.assertEqual(2, self.mock_dest_client.get_snapmirrors.call_count)

        self.mock_dest_client.quiesce_snapmirror.assert_called_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

        self.mock_dest_client.abort_snapmirror.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name,
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
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name,
            desired_attributes=['relationship-status', 'mirror-state']
        )
        self.assertEqual(2, self.mock_dest_client.get_snapmirrors.call_count)

        self.mock_dest_client.quiesce_snapmirror.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

    def test_resync_snapmirror(self):
        self.dm_session.resync_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        self.mock_dest_client.resync_snapmirror.assert_called_once_with(
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

        self.dm_session.change_snapmirror_source(
            self.fake_dest_share, self.fake_src_share, fake_new_src_share,
            [self.fake_dest_share, self.fake_src_share, fake_new_src_share])

        self.assertFalse(self.mock_src_client.release_snapmirror.called)

        self.assertEqual(4, self.dm_session.delete_snapmirror.call_count)
        self.dm_session.delete_snapmirror.assert_called_with(
            mock.ANY, mock.ANY, release=False
        )

        self.mock_dest_client.create_snapmirror.assert_called_once_with(
            mock.ANY, fake_new_src_share_name, mock.ANY,
            self.fake_dest_vol_name, schedule='hourly'
        )

        self.mock_dest_client.resync_snapmirror.assert_called_once_with(
            mock.ANY, fake_new_src_share_name, mock.ANY,
            self.fake_dest_vol_name
        )

    def test_get_snapmirrors(self):
        self.mock_object(self.mock_dest_client, 'get_snapmirrors')

        self.dm_session.get_snapmirrors(self.fake_src_share,
                                        self.fake_dest_share)

        self.mock_dest_client.get_snapmirrors.assert_called_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name,
            desired_attributes=['relationship-status',
                                'mirror-state',
                                'source-vserver',
                                'source-volume',
                                'last-transfer-end-timestamp']
        )
        self.assertEqual(1, self.mock_dest_client.get_snapmirrors.call_count)

    def test_update_snapmirror(self):
        self.mock_object(self.mock_dest_client, 'get_snapmirrors')

        self.dm_session.update_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        self.mock_dest_client.update_snapmirror.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)

    def test_resume_snapmirror(self):
        self.mock_object(self.mock_dest_client, 'get_snapmirrors')

        self.dm_session.resume_snapmirror(self.fake_src_share,
                                          self.fake_dest_share)

        self.mock_dest_client.resume_snapmirror.assert_called_once_with(
            self.source_vserver, self.fake_src_vol_name,
            self.dest_vserver, self.fake_dest_vol_name)
