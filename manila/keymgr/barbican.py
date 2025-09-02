# Copyright 2025 Cloudification GmbH.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import urllib

from barbicanclient import client as barbican_client
from castellan import options as castellan_options
from keystoneauth1 import identity as ks_identity
from keystoneauth1 import loading as ks_loading
from keystoneauth1 import session as ks_session
from keystoneclient.v3 import client as ks_client
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils

from manila import exception
from manila.i18n import _


BARBICAN_GROUP = 'barbican'

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

castellan_options.set_defaults(CONF)
ks_loading.register_auth_conf_options(CONF, BARBICAN_GROUP)


def _require_barbican_key_manager_backend(conf):
    backend = conf.key_manager.backend
    if backend is None:
        LOG.warning("The BarbicanKeyManager backend should be explicitly "
                    "used for share encryption.")
        raise exception.ManilaBarbicanACLError()

    backend = backend.split('.')[-1]
    if backend not in ('barbican', 'BarbicanKeyManager'):
        LOG.warning("The '%s' key_manager backend is not supported. Please"
                    " use barbican as key_manager.", backend)
        raise exception.ManilaBarbicanACLError()


class BarbicanSecretACL(object):
    def __init__(self, conf):
        self.conf = conf

    def get_client_and_href(self, context, secret_ref):
        """Get user barbican client and a secret href"""
        _require_barbican_key_manager_backend(self.conf)

        if not getattr(self.conf, 'barbican', None) or \
           not getattr(self.conf.barbican, 'auth_endpoint', None):
            LOG.error("Missing auth_endpoint for barbican connection")
            raise exception.ManilaBarbicanACLError()

        if not secret_ref:
            LOG.error("Missing secret_ref provided in current user context.")
            raise exception.ManilaBarbicanACLError()

        # Establish a Barbican client session of current user and keystone
        # session of barbican user to get its user_id. Grant ACL to barbican
        # user that it will be used for the key_ref handover process.
        try:
            user_auth = ks_identity.V3Token(
                auth_url=self.conf.barbican.auth_endpoint,
                token=context.auth_token,
                project_id=context.project_id)
            user_sess = ks_session.Session(auth=user_auth)
            user_barbican_client = barbican_client.Client(session=user_sess)

            barbican_endpoint = self._get_barbican_endpoint(user_auth,
                                                            user_sess)
            base_url = self._create_base_url(user_auth, user_sess,
                                             barbican_endpoint)
            secret_ref = self._create_secret_ref(base_url, secret_ref)
        except Exception as e:
            LOG.error("Failed to create barbican client. Error: %s", e)
            raise exception.ManilaBarbicanACLError()

        return user_barbican_client, secret_ref

    def create_secret_access(self, context, secret_ref):
        try:
            user_barbican_client, secret_href = self.get_client_and_href(
                context, secret_ref)
            barbican_auth = ks_loading.load_auth_from_conf_options(
                self.conf, BARBICAN_GROUP)
            barbican_sess = ks_session.Session(auth=barbican_auth)
            barbican_ks_client = ks_client.Client(session=barbican_sess)
            barbican_user_id = barbican_ks_client.session.get_user_id()

            # Create a Barbican ACL so the barbican user can access it.
            acl = user_barbican_client.acls.create(entity_ref=secret_href,
                                                   users=[barbican_user_id],
                                                   project_access=False)
            acl.submit()
        except Exception as e:
            LOG.error("Failed to create secret ACL. Error: %s", e)
            raise exception.ManilaBarbicanACLError()

    def delete_secret_access(self, context, secret_ref):
        try:
            user_barbican_client, secret_href = self.get_client_and_href(
                context, secret_ref)
            barbican_auth = ks_loading.load_auth_from_conf_options(
                self.conf, BARBICAN_GROUP)
            barbican_sess = ks_session.Session(auth=barbican_auth)
            barbican_ks_client = ks_client.Client(session=barbican_sess)
            barbican_user_id = barbican_ks_client.session.get_user_id()

            # Remove a Barbican ACL for the barbican user.
            acl_entity = user_barbican_client.acls.get(entity_ref=secret_href)
            existing_users = acl_entity.read.users
            remove_users = [barbican_user_id]
            updated_users = set(existing_users).difference(remove_users)
            acl_entity.read.users = list(updated_users)

            acl_entity.submit()
        except Exception as e:
            LOG.error("Failed to delete secret ACL. Error: %s", e)

    def get_secret_href(self, context, secret_ref):
        try:
            user_barbican_client, secret_href = self.get_client_and_href(
                context, secret_ref)
            return secret_href
        except Exception as e:
            LOG.error("Failed to get barbican secret href. Error: %s", e)
            raise exception.ManilaBarbicanACLError()

    def _get_barbican_endpoint(self, auth, sess):
        if self.conf.barbican.barbican_endpoint:
            return self.conf.barbican.barbican_endpoint
        elif getattr(auth, 'service_catalog', None):
            endpoint_data = auth.service_catalog.endpoint_data_for(
                service_type='key-manager',
                interface=self.conf.barbican.barbican_endpoint_type,
                region_name=self.conf.barbican.barbican_region_name)
            return endpoint_data.url
        else:
            return auth.get_endpoint(
                sess,
                service_type='key-manager',
                interface=self.conf.barbican.barbican_endpoint_type,
                region_name=self.conf.barbican.barbican_region_name)

    def _create_base_url(self, auth, sess, endpoint):
        api_version = None
        if self.conf.barbican.barbican_api_version:
            api_version = self.conf.barbican.barbican_api_version
        elif getattr(auth, 'service_catalog', None):
            endpoint_data = auth.service_catalog.endpoint_data_for(
                service_type='key-manager',
                interface=self.conf.barbican.barbican_endpoint_type,
                region_name=self.conf.barbican.barbican_region_name)
            api_version = endpoint_data.api_version
        elif getattr(auth, 'get_discovery', None):
            discovery = auth.get_discovery(sess, url=endpoint)
            raw_data = discovery.raw_version_data()
            if len(raw_data) == 0:
                msg = _(
                    "Could not find discovery information for %s") % endpoint
                LOG.error(msg)
                raise exception.KeyManagerError(reason=msg)
            latest_version = raw_data[-1]
            api_version = latest_version.get('id')

        if not endpoint.endswith('/'):
            endpoint += '/'

        base_url = urllib.parse.urljoin(endpoint, api_version)
        return base_url

    def _create_secret_ref(self, base_url, object_id):
        if not object_id:
            msg = _("Key ID is None")
            raise exception.KeyManagerError(reason=msg)
        if not base_url.endswith('/'):
            base_url += '/'
        return urllib.parse.urljoin(base_url, "secrets/" + object_id)


class BarbicanUserAppCreds(object):
    def __init__(self, conf):
        self.conf = conf

    @property
    def client(self):
        return self.get_client()

    def get_client(self):
        _require_barbican_key_manager_backend(self.conf)
        auth = ks_loading.load_auth_from_conf_options(self.conf,
                                                      BARBICAN_GROUP)
        sess = ks_session.Session(auth=auth)
        return ks_client.Client(session=sess)

    def get_application_credentials(self, context, application_credential_id):
        if not application_credential_id:
            LOG.warning("Missing application credentials ID")
            raise exception.ManilaBarbicanAppCredsError()

        try:
            return self.client.application_credentials.get(
                application_credential=application_credential_id)
        except Exception as e:
            LOG.error("Aborting App Creds request due to error: %s", e)
            raise exception.ManilaBarbicanAppCredsError()

    def create_application_credentials(self, context, secret):
        try:
            secrets_path = "/key-manager/v1/secrets"
            return self.client.application_credentials.create(
                name='manila_barbican_' + uuidutils.generate_uuid(),
                user=self.client.session.get_user_id(),
                roles=[{'name': 'service'}],
                secret=str(secret),
                access_rules=[
                    {
                        "path": secrets_path + "/%s" % secret,
                        "method": "GET",
                        "service": "key-manager",
                    },
                    {
                        "path": secrets_path + "/%s/payload" % secret,
                        "method": "GET",
                        "service": "key-manager",
                    }
                ]
            )
        except Exception as e:
            LOG.error("Aborting App Creds create due to error: %s", e)
            raise exception.ManilaBarbicanAppCredsError()

    def delete_application_credentials(self, context,
                                       application_credential_id):
        if not application_credential_id:
            LOG.warning("Missing application credentials ID")
            raise exception.ManilaBarbicanAppCredsError()

        try:
            return self.client.application_credentials.delete(
                application_credential=application_credential_id)
        except Exception as e:
            LOG.error("Aborting App Creds request due to error: %s", e)
            raise exception.ManilaBarbicanAppCredsError()


def create_secret_access(context, secret_ref, conf=CONF):
    BarbicanSecretACL(conf).create_secret_access(context, secret_ref)


def delete_secret_access(context, secret_ref, conf=CONF):
    BarbicanSecretACL(conf).delete_secret_access(context, secret_ref)


def get_secret_href(context, secret_ref, conf=CONF):
    return BarbicanSecretACL(conf).get_secret_href(context, secret_ref)


def create_application_credentials(context, secret, conf=CONF):
    return BarbicanUserAppCreds(conf).create_application_credentials(
        context,
        secret)


def get_application_credentials(context, application_credential_id, conf=CONF):
    return BarbicanUserAppCreds(conf).get_application_credentials(
        context,
        application_credential_id)


def delete_application_credentials(context,
                                   application_credential_id, conf=CONF):
    BarbicanUserAppCreds(conf).delete_application_credentials(
        context,
        application_credential_id)
