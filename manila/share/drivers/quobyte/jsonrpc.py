# Copyright (c) 2015 Quobyte Inc.
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

"""Quobyte driver helper.

Control Quobyte over its JSON RPC API.
"""

import requests
from requests import auth
from requests import codes

from oslo_log import log
from oslo_serialization import jsonutils
import six
import six.moves.urllib.parse as urlparse

from manila import exception
from manila import utils

LOG = log.getLogger(__name__)

ERROR_ENOENT = 2
ERROR_ENTITY_NOT_FOUND = -24
ERROR_GARBAGE_ARGS = -3


class JsonRpc(object):

    def __init__(self, url, user_credentials, ca_file=None, key_file=None,
                 cert_file=None):
        parsedurl = urlparse.urlparse(url)
        self._url = parsedurl.geturl()
        self._netloc = parsedurl.netloc
        self._ca_file = ca_file
        self._url_scheme = parsedurl.scheme
        if self._url_scheme == 'https':
            if not self._ca_file:
                self._ca_file = False
                LOG.warning(
                    "Will not verify the server certificate of the API service"
                    " because the CA certificate is not available.")
        self._id = 0
        self._credentials = auth.HTTPBasicAuth(
            user_credentials[0], user_credentials[1])
        self._key_file = key_file
        self._cert_file = cert_file

    @utils.synchronized('quobyte-request')
    def call(self, method_name, user_parameters, expected_errors=None):
        if expected_errors is None:
            expected_errors = []
        # prepare request
        self._id += 1
        parameters = {'retry': 'INFINITELY'}  # Backend specific setting
        if user_parameters:
            parameters.update(user_parameters)
        post_data = {
            'jsonrpc': '2.0',
            'method': method_name,
            'params': parameters,
            'id': six.text_type(self._id),
        }
        LOG.debug("Request payload to be send is: %s",
                  jsonutils.dumps(post_data))

        # send request
        if self._url_scheme == 'https':
            if self._cert_file:
                result = requests.post(url=self._url,
                                       json=post_data,
                                       auth=self._credentials,
                                       verify=self._ca_file,
                                       cert=(self._cert_file, self._key_file))
            else:
                result = requests.post(url=self._url,
                                       json=post_data,
                                       auth=self._credentials,
                                       verify=self._ca_file)
        else:
            result = requests.post(url=self._url,
                                   json=post_data,
                                   auth=self._credentials)

        # eval request response
        if result.status_code == codes['OK']:
            LOG.debug("Retrieved data from Quobyte backend: %s", result.text)
            response = result.json()
            return self._checked_for_application_error(response,
                                                       expected_errors)

        # If things did not work out provide error info
        LOG.debug("Backend request resulted in error: %s", result.text)
        result.raise_for_status()

    def _checked_for_application_error(self, result, expected_errors=None):
        if expected_errors is None:
            expected_errors = []
        if 'error' in result and result['error']:
            if 'message' in result['error'] and 'code' in result['error']:
                if result["error"]["code"] in expected_errors:
                    # hit an expected error, return empty result
                    return None
                else:
                    raise exception.QBRpcException(
                        result=result["error"]["message"],
                        qbcode=result["error"]["code"])
            else:
                raise exception.QBException(six.text_type(result["error"]))
        return result["result"]
