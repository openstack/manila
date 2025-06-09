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
from oslo_utils import uuidutils

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

    @mock.patch('barbicanclient.client.Client')
    @mock.patch('keystoneauth1.session.Session')
    @mock.patch('keystoneauth1.identity.v3.Token')
    def test_get_client_and_href_with_valid_secret(self, mock_token,
                                                   mock_session, mock_client):
        mock_href = uuidutils.generate_uuid()
        mock_instance = mock.Mock()
        mock_client.return_value = mock_instance
        self.mock_object(self.barbican_acl, '_get_barbican_endpoint')
        self.mock_object(self.barbican_acl, '_create_base_url')
        self.mock_object(self.barbican_acl, '_create_secret_ref',
                         mock.Mock(return_value=mock_href))

        result_client, result_href = self.barbican_acl.get_client_and_href(
            self.context, mock_href)
        self.assertEqual(mock_instance, result_client)
        self.assertIn(mock_href, result_href)

    def test_get_client_and_href_missing_backend(self):
        CONF.set_default('backend', 'wrong.backend', group='key_manager')
        self.assertRaises(
            exception.ManilaBarbicanACLError,
            self.barbican_acl.get_client_and_href,
            self.context,
            self.secret_ref)

    def test_get_client_and_href_missing_secret_ref(self):
        self.assertRaises(
            exception.ManilaBarbicanACLError,
            self.barbican_acl.get_client_and_href,
            self.context,
            None)


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
