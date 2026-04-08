# Copyright 2025 Cloudification GmbH.
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

from unittest import mock

from oslo_config import cfg

from manila import exception
from manila.keymgr import barbican as barbican_module
from manila import test

CONF = cfg.CONF


class BarbicanSecretACLTestCase(test.TestCase):

    def setUp(self):
        super(BarbicanSecretACLTestCase, self).setUp()
        self.context = mock.Mock()
        self.secret_ref = 'mock-secret-id'
        self.barbican_acl = barbican_module.BarbicanSecretACL(CONF)

    def test_get_client_with_valid_secret(self):
        mock_client = mock.Mock()
        self.mock_object(self.barbican_acl, '_get_barbican_client',
                         mock.Mock(return_value=(mock_client, mock.Mock())))

        result_client = self.barbican_acl.get_client(self.context)
        self.assertEqual(mock_client, result_client)

    def test_get_client_missing_backend(self):
        CONF.set_default('backend', 'wrong.backend', group='key_manager')
        self.assertRaises(
            exception.ManilaBarbicanACLError,
            self.barbican_acl.get_client,
            self.context)


class BarbicanUserAppCredsTestCase(test.TestCase):

    def setUp(self):
        super(BarbicanUserAppCredsTestCase, self).setUp()
        self.context = mock.Mock()
        self.app_creds = barbican_module.BarbicanUserAppCreds(CONF)

    @mock.patch('keystoneclient.v3.client.Client')
    @mock.patch('keystoneauth1.session.Session')
    @mock.patch('keystoneauth1.loading.load_auth_from_conf_options')
    def test_get_application_credentials_success(self, mock_auth,
                                                 mock_session, mock_client):
        fake_cred = mock.Mock()
        mock_instance = mock.Mock()
        mock_instance.application_credentials.get.return_value = fake_cred
        mock_client.return_value = mock_instance

        result = self.app_creds.get_application_credentials(
            self.context, 'fake_id')
        self.assertEqual(fake_cred, result)

    def test_get_application_credentials_missing_id(self):
        self.assertRaises(
            exception.ManilaBarbicanAppCredsError,
            self.app_creds.get_application_credentials,
            self.context,
            None)

    @mock.patch('keystoneclient.v3.client.Client')
    @mock.patch('keystoneauth1.session.Session')
    @mock.patch('keystoneauth1.loading.load_auth_from_conf_options')
    def test_delete_application_credentials(self, mock_auth,
                                            mock_session, mock_client):
        mock_instance = mock.Mock()
        mock_client.return_value = mock_instance
        self.app_creds.delete_application_credentials(self.context, 'cred_id')
        mock_instance.application_credentials.delete.assert_called_once()

    def test_delete_application_credentials_missing_id(self):
        self.assertRaises(
            exception.ManilaBarbicanAppCredsError,
            self.app_creds.delete_application_credentials,
            self.context,
            None)

    @mock.patch('manila.keymgr.barbican.get_secret_href')
    @mock.patch('keystoneclient.v3.client.Client')
    @mock.patch('keystoneauth1.session.Session')
    @mock.patch('keystoneauth1.loading.load_auth_from_conf_options')
    def test_create_application_credentials_success(self, mock_auth,
                                                    mock_session,
                                                    mock_ks_client,
                                                    mock_get_href):
        fake_secret = 'fake-secret-uuid'
        fake_href = 'http://barbican:9311/v1/secrets/' + fake_secret
        fake_cred = mock.Mock()

        mock_get_href.return_value = fake_href
        mock_client_instance = mock.Mock()
        mock_client_instance.session.get_user_id.return_value = 'fake-user-id'
        mock_client_instance.application_credentials.create.return_value = (
            fake_cred)
        mock_ks_client.return_value = mock_client_instance

        result = self.app_creds.create_application_credentials(
            self.context, fake_secret)

        self.assertEqual(fake_cred, result)
        mock_get_href.assert_called_once_with(
            self.context, fake_secret, conf=CONF)
        mock_creds = mock_client_instance.application_credentials
        mock_creds.create.assert_called_once()
        args, kwargs = mock_creds.create.call_args
        access_rules = kwargs['access_rules']
        self.assertEqual('/v1/secrets/' + fake_secret,
                         access_rules[0]['path'])
        self.assertEqual('/v1/secrets/' + fake_secret + '/payload',
                         access_rules[1]['path'])

    @mock.patch('manila.keymgr.barbican.get_secret_href')
    @mock.patch('keystoneclient.v3.client.Client')
    @mock.patch('keystoneauth1.session.Session')
    @mock.patch('keystoneauth1.loading.load_auth_from_conf_options')
    def test_create_application_credentials_href_error(
            self, mock_auth, mock_session, mock_ks_client,
            mock_get_href):
        mock_get_href.side_effect = exception.ManilaBarbicanACLError()
        mock_ks_client.return_value = mock.Mock()

        self.assertRaises(
            exception.ManilaBarbicanAppCredsError,
            self.app_creds.create_application_credentials,
            self.context,
            'fake-secret-uuid')

    @mock.patch('manila.keymgr.barbican.get_secret_href')
    @mock.patch('keystoneclient.v3.client.Client')
    @mock.patch('keystoneauth1.session.Session')
    @mock.patch('keystoneauth1.loading.load_auth_from_conf_options')
    def test_create_application_credentials_exception(self, mock_auth,
                                                      mock_session,
                                                      mock_ks_client,
                                                      mock_get_href):
        fake_secret = 'fake-secret-uuid'
        fake_href = 'http://barbican:9311/v1/secrets/' + fake_secret
        mock_get_href.return_value = fake_href

        mock_client_instance = mock.Mock()
        mock_client_instance.application_credentials.create.side_effect = (
            Exception("create failed"))
        mock_ks_client.return_value = mock_client_instance

        self.assertRaises(
            exception.ManilaBarbicanAppCredsError,
            self.app_creds.create_application_credentials,
            self.context,
            fake_secret)
