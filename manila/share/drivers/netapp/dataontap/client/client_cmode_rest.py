# Copyright (c) 2023 NetApp, Inc. All rights reserved.
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

from http import client as http_client

from oslo_log import log

from manila import exception
from manila.i18n import _
from manila.share.drivers.netapp.dataontap.client import client_base
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.client import rest_api as netapp_api
from manila.share.drivers.netapp import utils as na_utils
from manila import utils


LOG = log.getLogger(__name__)
DEFAULT_MAX_PAGE_LENGTH = 10000


class NetAppRestClient(object):

    def __init__(self, **kwargs):

        self.connection = netapp_api.RestNaServer(
            host=kwargs['hostname'],
            transport_type=kwargs['transport_type'],
            ssl_cert_path=kwargs['ssl_cert_path'],
            port=kwargs['port'],
            username=kwargs['username'],
            password=kwargs['password'],
            trace=kwargs.get('trace', False),
            api_trace_pattern=kwargs.get('api_trace_pattern',
                                         na_utils.API_TRACE_PATTERN))

        self.async_rest_timeout = kwargs.get('async_rest_timeout', 60)

        self.vserver = kwargs.get('vserver', None)

        self.connection.set_vserver(self.vserver)

        ontap_version = self.get_ontap_version(cached=False)
        if ontap_version['version-tuple'] < (9, 11, 1):
            msg = _('This driver can communicate with ONTAP via REST APIs '
                    'exclusively only when paired with a NetApp ONTAP storage '
                    'system running release 9.11.1 or newer. '
                    'To use ZAPI and supported REST APIs instead, '
                    'set "netapp_use_legacy_client" to True.')
            raise exception.NetAppException(msg)
        self.connection.set_ontap_version(ontap_version)

        # NOTE(nahimsouza): ZAPI Client is needed to implement the fallback
        # when a REST method is not supported.
        self.zapi_client = client_cmode.NetAppCmodeClient(**kwargs)

        self._init_features()

    def _init_features(self):
        """Initialize feature support map."""
        self.features = client_base.Features()

        # NOTE(felipe_rodrigues): REST client only runs with ONTAP 9.11.1 or
        # upper, so all features below are supported with this client.
        self.features.add_feature('SNAPMIRROR_V2', supported=True)
        self.features.add_feature('SYSTEM_METRICS', supported=True)
        self.features.add_feature('SYSTEM_CONSTITUENT_METRICS',
                                  supported=True)
        self.features.add_feature('BROADCAST_DOMAINS', supported=True)
        self.features.add_feature('IPSPACES', supported=True)
        self.features.add_feature('SUBNETS', supported=True)
        self.features.add_feature('CLUSTER_PEER_POLICY', supported=True)
        self.features.add_feature('ADVANCED_DISK_PARTITIONING',
                                  supported=True)
        self.features.add_feature('KERBEROS_VSERVER', supported=True)
        self.features.add_feature('FLEXVOL_ENCRYPTION', supported=True)
        self.features.add_feature('SVM_DR', supported=True)
        self.features.add_feature('ADAPTIVE_QOS', supported=True)
        self.features.add_feature('TRANSFER_LIMIT_NFS_CONFIG',
                                  supported=True)
        self.features.add_feature('CIFS_DC_ADD_SKIP_CHECK',
                                  supported=True)
        self.features.add_feature('LDAP_LDAP_SERVERS',
                                  supported=True)
        self.features.add_feature('FLEXGROUP', supported=True)
        self.features.add_feature('FLEXGROUP_FAN_OUT', supported=True)
        self.features.add_feature('SVM_MIGRATE', supported=True)

    def __getattr__(self, name):
        """If method is not implemented for REST, try to call the ZAPI."""
        LOG.debug("The %s call is not supported for REST, falling back to "
                  "ZAPI.", name)
        # Don't use self.zapi_client to avoid reentrant call to __getattr__()
        zapi_client = object.__getattribute__(self, 'zapi_client')
        return getattr(zapi_client, name)

    def _wait_job_result(self, job_url):

        interval = 2
        retries = (self.async_rest_timeout / interval)

        @utils.retry(netapp_api.NaRetryableError, interval=interval,
                     retries=retries, backoff_rate=1)
        def _waiter():
            response = self.send_request(job_url, 'get',
                                         enable_tunneling=False)

            job_state = response.get('state')
            if job_state == 'success':
                return response
            elif job_state == 'failure':
                message = response['error']['message']
                code = response['error']['code']
                raise netapp_api.NaRetryableError(message=message, code=code)

            msg_args = {'job': job_url, 'state': job_state}
            LOG.debug("Job %(job)s has not finished: %(state)s", msg_args)
            raise netapp_api.NaRetryableError(message='Job is running.')

        try:
            return _waiter()
        except netapp_api.NaRetryableError:
            msg = _("Job %s did not reach the expected state. Retries "
                    "exhausted. Aborting.") % job_url
            raise na_utils.NetAppDriverException(msg)

    def send_request(self, action_url, method, body=None, query=None,
                     enable_tunneling=True,
                     max_page_length=DEFAULT_MAX_PAGE_LENGTH,
                     wait_on_accepted=True):

        """Sends REST request to ONTAP.

        :param action_url: action URL for the request
        :param method: HTTP method for the request ('get', 'post', 'put',
            'delete' or 'patch')
        :param body: dict of arguments to be passed as request body
        :param query: dict of arguments to be passed as query string
        :param enable_tunneling: enable tunneling to the ONTAP host
        :param max_page_length: size of the page during pagination
        :param wait_on_accepted: if True, wait until the job finishes when
            HTTP code 202 (Accepted) is returned

        :returns: parsed REST response
        """

        response = None

        if method == 'get':
            response = self.get_records(
                action_url, query, enable_tunneling, max_page_length)
        else:
            code, response = self.connection.invoke_successfully(
                action_url, method, body=body, query=query,
                enable_tunneling=enable_tunneling)

            if code == http_client.ACCEPTED and wait_on_accepted:
                # get job URL and discard '/api'
                job_url = response['job']['_links']['self']['href'][4:]
                response = self._wait_job_result(job_url)

        return response

    def get_records(self, action_url, query=None, enable_tunneling=True,
                    max_page_length=DEFAULT_MAX_PAGE_LENGTH):
        """Retrieves ONTAP resources using pagination REST request.

        :param action_url: action URL for the request
        :param query: dict of arguments to be passed as query string
        :param enable_tunneling: enable tunneling to the ONTAP host
        :param max_page_length: size of the page during pagination

        :returns: dict containing records and num_records
        """

        # Initialize query variable if it is None
        query = query if query else {}
        query['max_records'] = max_page_length

        _, response = self.connection.invoke_successfully(
            action_url, 'get', query=query,
            enable_tunneling=enable_tunneling)

        # NOTE(nahimsouza): if all records are returned in the first call,
        # 'next_url' will be None.
        next_url = response.get('_links', {}).get('next', {}).get('href')
        next_url = next_url[4:] if next_url else None  # discard '/api'

        # Get remaining pages, saving data into first page
        while next_url:
            # NOTE(nahimsouza): clean the 'query', because the parameters are
            # already included in 'next_url'.
            _, next_response = self.connection.invoke_successfully(
                next_url, 'get', query=None,
                enable_tunneling=enable_tunneling)

            response['num_records'] += next_response.get('num_records', 0)
            response['records'].extend(next_response.get('records'))

            next_url = (
                next_response.get('_links', {}).get('next', {}).get('href'))
            next_url = next_url[4:] if next_url else None  # discard '/api'

        return response

    def get_ontap_version(self, cached=True):
        """Get the current Data ONTAP version."""

        if cached:
            return self.connection.get_ontap_version()

        query = {
            'fields': 'version'
        }
        response = self.send_request('/cluster/nodes', 'get', query=query)
        records = response.get('records')[0]

        return {
            'version': records['version']['full'],
            'version-tuple': (records['version']['generation'],
                              records['version']['major'],
                              records['version']['minor']),
        }
