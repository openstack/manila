# Copyright 2023 NetApp, Inc. All Rights Reserved.
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
"""
NetApp API for REST Data ONTAP.

Contains classes required to issue REST API calls to Data ONTAP.
"""

import re

from oslo_log import log
from oslo_serialization import jsonutils
import requests
from requests.adapters import HTTPAdapter
from requests import auth
from urllib3.util import retry

from manila.share.drivers.netapp.dataontap.client import api
from manila.share.drivers.netapp import utils


LOG = log.getLogger(__name__)

EREST_DUPLICATE_ENTRY = '1'
EREST_ENTRY_NOT_FOUND = '4'
EREST_NOT_AUTHORIZED = '6'
EREST_SNAPMIRROR_INITIALIZING = '917536'
EREST_VSERVER_NOT_FOUND = '13434920'
EREST_ANOTHER_VOLUME_OPERATION = '13107406'
EREST_LICENSE_NOT_INSTALLED = '1115127'
EREST_SNAPSHOT_NOT_SPECIFIED = '1638515'
EREST_FPOLICY_MODIF_POLICY_DISABLED = '9765029'
EREST_POLICY_ALREADY_DISABLED = '9764907'
EREST_ERELATION_EXISTS = '6619637'
EREST_BREAK_SNAPMIRROR_FAILED = '13303808'
EREST_UPDATE_SNAPMIRROR_FAILED = '13303844'
EREST_SNAPMIRROR_NOT_INITIALIZED = '13303812'
EREST_DUPLICATE_ROUTE = '1966345'
EREST_FAIL_ADD_PORT_BROADCAST = '1967149'
EREST_KERBEROS_IS_ENABLED_DISABLED = '3276861'
EREST_INTERFACE_BOUND = '1376858'
EREST_PORT_IN_USE = '1966189'
EREST_NFS_V4_0_ENABLED_MIGRATION_FAILURE = '13172940'
EREST_VSERVER_MIGRATION_TO_NON_AFF_CLUSTER = '13172984'
EREST_UNMOUNT_FAILED_LOCK = '917536'
EREST_CANNOT_MODITY_OFFLINE_VOLUME = '917533'


class NaRetryableError(api.NaApiError):
    def __str__(self, *args, **kwargs):
        return 'NetApp API failed. Try again. Reason - %s:%s' % (
            self.code, self.message)


class RestNaServer(object):

    TRANSPORT_TYPE_HTTP = 'http'
    TRANSPORT_TYPE_HTTPS = 'https'
    HTTP_PORT = '80'
    HTTPS_PORT = '443'
    TUNNELING_HEADER_KEY = "X-Dot-SVM-Name"

    def __init__(self, host, transport_type=TRANSPORT_TYPE_HTTP,
                 ssl_cert_path=None, username=None, password=None, port=None,
                 trace=False, api_trace_pattern=utils.API_TRACE_PATTERN):
        self._host = host
        self.set_transport_type(transport_type)
        self.set_port(port=port)
        self._username = username
        self._password = password
        self._trace = trace
        self._api_trace_pattern = api_trace_pattern
        self._timeout = None

        if ssl_cert_path is not None:
            self._ssl_verify = ssl_cert_path
        else:
            # Note(felipe_rodrigues): it will verify with the mozila CA roots,
            # given by certifi package.
            self._ssl_verify = True

        LOG.debug('Using REST with NetApp controller: %s', self._host)

    def set_transport_type(self, transport_type):
        """Set the transport type protocol for API.

        Supports http and https transport types.
        """
        if transport_type is None or transport_type.lower() not in (
                RestNaServer.TRANSPORT_TYPE_HTTP,
                RestNaServer.TRANSPORT_TYPE_HTTPS):
            raise ValueError('Unsupported transport type')
        self._protocol = transport_type.lower()

    def get_transport_type(self):
        """Get the transport type protocol."""
        return self._protocol

    def set_api_version(self, major, minor):
        """Set the API version."""
        try:
            self._api_major_version = int(major)
            self._api_minor_version = int(minor)
            self._api_version = str(major) + "." + str(minor)
        except ValueError:
            raise ValueError('Major and minor versions must be integers')

    def get_api_version(self):
        """Gets the API version tuple."""
        if hasattr(self, '_api_version'):
            return (self._api_major_version, self._api_minor_version)
        return None

    def set_ontap_version(self, ontap_version):
        """Set the ONTAP version."""
        self._ontap_version = ontap_version

    def get_ontap_version(self):
        """Gets the ONTAP version."""
        if hasattr(self, '_ontap_version'):
            return self._ontap_version
        return None

    def set_port(self, port=None):
        """Set the ONTAP port, if not informed, set with default one."""
        if port is None and self._protocol == RestNaServer.TRANSPORT_TYPE_HTTP:
            self._port = RestNaServer.HTTP_PORT
        elif port is None:
            self._port = RestNaServer.HTTPS_PORT
        else:
            try:
                int(port)
            except ValueError:
                raise ValueError('Port must be integer')
            self._port = str(port)

    def get_port(self):
        """Get the server communication port."""
        return self._port

    def set_timeout(self, seconds):
        """Sets the timeout in seconds."""
        try:
            self._timeout = int(seconds)
        except ValueError:
            raise ValueError('timeout in seconds must be integer')

    def get_timeout(self):
        """Gets the timeout in seconds if set."""
        return self._timeout

    def set_vserver(self, vserver):
        """Set the vserver to use if tunneling gets enabled."""
        self._vserver = vserver

    def get_vserver(self):
        """Get the vserver to use in tunneling."""
        return self._vserver

    def __str__(self):
        """Gets a representation of the client."""
        return "server: %s" % (self._host)

    def _get_request_method(self, method, session):
        """Returns the request method to be used in the REST call."""

        request_methods = {
            'post': session.post,
            'get': session.get,
            'put': session.put,
            'delete': session.delete,
            'patch': session.patch,
        }
        return request_methods[method]

    def _add_query_params_to_url(self, url, query):
        """Populates the URL with specified filters."""
        filters = '&'.join([f"{k}={v}" for k, v in query.items()])
        url += "?" + filters
        return url

    def _get_base_url(self):
        """Get the base URL for REST requests."""
        host = self._host
        if ':' in host:
            host = '[%s]' % host
        return f'{self._protocol}://{host}:{self._port}/api'

    def _build_session(self, headers):
        """Builds a session in the client."""
        self._session = requests.Session()

        # NOTE(felipe_rodrigues): request resilient of temporary network
        # failures (like name resolution failure), retrying until 5 times.
        max_retries = retry.Retry(total=5, connect=5, read=2, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=max_retries)
        self._session.mount('%s://' % self._protocol, adapter)

        self._session.auth = self._create_basic_auth_handler()
        self._session.verify = self._ssl_verify
        self._session.headers = headers

    def _build_headers(self, enable_tunneling):
        """Build and return headers for a REST request."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        # enable tunneling only if vserver is set by upper layer
        if enable_tunneling and self.get_vserver:
            headers[RestNaServer.TUNNELING_HEADER_KEY] = self.get_vserver()

        return headers

    def _create_basic_auth_handler(self):
        """Creates and returns a basic HTTP auth handler."""
        return auth.HTTPBasicAuth(self._username, self._password)

    def send_http_request(self, method, url, body, headers):
        """Invoke the API on the server."""
        data = jsonutils.dumps(body) if body else {}

        self._build_session(headers)
        request_method = self._get_request_method(method, self._session)

        api_name_matches_regex = (re.match(self._api_trace_pattern, url)
                                  is not None)
        if self._trace and api_name_matches_regex:
            svm = headers.get(RestNaServer.TUNNELING_HEADER_KEY)
            message = ("Request: %(method)s Header=%(header)s %(url)s "
                       "Body=%(body)s")
            msg_args = {
                "method": method.upper(),
                "url": url,
                "body": body,
                "header": ({RestNaServer.TUNNELING_HEADER_KEY: svm}
                           if svm else {}),
            }
            LOG.debug(message, msg_args)

        try:
            if self._timeout is not None:
                response = request_method(
                    url, data=data, timeout=self._timeout)
            else:
                response = request_method(url, data=data)
        except requests.HTTPError as e:
            raise api.NaApiError(e.errno, e.strerror)
        except Exception as e:
            raise api.NaApiError(message=e)

        code = response.status_code
        res = jsonutils.loads(response.content) if response.content else {}

        if self._trace and api_name_matches_regex:
            message = "Response: %(code)s Body=%(body)s"
            msg_args = {
                "code": code,
                "body": res
            }
            LOG.debug(message, msg_args)

        return code, res

    def invoke_successfully(self, action_url, method, body=None, query=None,
                            enable_tunneling=False):
        """Invokes REST API and checks execution status as success."""
        headers = self._build_headers(enable_tunneling)
        if query:
            action_url = self._add_query_params_to_url(action_url, query)
        url = self._get_base_url() + action_url
        code, response = self.send_http_request(method, url, body, headers)

        if not response.get('error'):
            return code, response

        result_error = response.get('error')
        code = result_error.get('code') or 'ESTATUSFAILED'
        msg = (result_error.get('message')
               or 'Execution failed due to unknown reason')
        raise api.NaApiError(code, msg)
