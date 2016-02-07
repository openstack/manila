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

import base64
import socket
import ssl

from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import excutils
import six
from six.moves import http_client
import six.moves.urllib.parse as urlparse

from manila import exception
from manila.i18n import _, _LW

LOG = log.getLogger(__name__)

ERROR_ENOENT = 2

CONNECTION_RETRIES = 3


class BasicAuthCredentials(object):
    def __init__(self, username, password):
        self._username = username
        self._password = password

    @property
    def username(self):
        return self._username

    def get_authorization_header(self):
        header = '%s:%s' % (self._username, self._password)
        auth = base64.standard_b64encode(six.b(header))
        return 'BASIC %s' % auth.decode()


class HTTPSConnectionWithCaVerification(http_client.HTTPConnection):
    """Verify server cert against a given CA certificate."""

    default_port = http_client.HTTPS_PORT

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 ca_file=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        http_client.HTTPConnection.__init__(self, host, port, timeout=timeout)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_file = ca_file

    def connect(self):
        """Connect to a host on a given (SSL) port."""
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock, keyfile=self.key_file,
                                    certfile=self.cert_file,
                                    ca_certs=self.ca_file,
                                    cert_reqs=ssl.CERT_REQUIRED)

    http_client.__all__.append("HTTPSConnectionWithCaVerification")


class JsonRpc(object):
    def __init__(self, url, user_credentials, ca_file=None):
        parsedurl = urlparse.urlparse(url)
        self._url = parsedurl.geturl()
        self._netloc = parsedurl.netloc
        self._ca_file = ca_file
        if parsedurl.scheme == 'https':
            if self._ca_file:
                self._connection = HTTPSConnectionWithCaVerification(
                    self._netloc,
                    ca_file=self._ca_file.name)
            else:
                self._connection = http_client.HTTPSConnection(self._netloc)
                LOG.warning(_LW(
                    "Will not verify the server certificate of the API service"
                    " because the CA certificate is not available."))
        else:
            self._connection = http_client.HTTPConnection(self._netloc)
        self._id = 0
        self._fail_fast = True
        self._credentials = BasicAuthCredentials(
            user_credentials[0], user_credentials[1])
        self._require_cert_verify = self._ca_file is not None
        self._disabled_cert_verification = False

    def call(self, method_name, user_parameters):

        parameters = {'retry': 'INFINITELY'}  # Backend specific setting
        if user_parameters:
            parameters.update(user_parameters)
        call_body = {'jsonrpc': '2.0',
                     'method': method_name,
                     'params': parameters,
                     'id': six.text_type(self._id)}
        self.call_counter = 0
        self._connection.connect()  # prevents http_client timing issue

        while self.call_counter < CONNECTION_RETRIES:
            self.call_counter += 1
            try:
                self._id += 1
                call_body['id'] = six.text_type(self._id)
                LOG.debug("Posting to Quobyte backend: %s",
                          jsonutils.dumps(call_body))
                self._connection.request(
                    "POST", self._url + '/', jsonutils.dumps(call_body),
                    dict(Authorization=(self._credentials.
                                        get_authorization_header())))

                response = self._connection.getresponse()
                self._throw_on_http_error(response)
                result = jsonutils.loads(response.read())
                LOG.debug("Retrieved data from Quobyte backend: %s", result)
                return self._checked_for_application_error(result)
            except ssl.SSLError as e:
                # Generic catch because OpenSSL does not return
                # meaningful errors.
                if (not self._disabled_cert_verification
                        and not self._require_cert_verify):
                    LOG.warning(_LW(
                        "Could not verify server certificate of "
                        "API service against CA."))
                    self._connection.close()
                    # Core HTTPSConnection does no certificate verification.
                    self._connection = http_client.HTTPSConnection(
                        self._netloc)
                    self._disabled_cert_verification = True
                else:
                    raise exception.QBException(_(
                        "Client SSL subsystem returned error: %s") % e)
            except http_client.BadStatusLine as e:
                raise exception.QBException(_(
                    "If SSL is enabled for the API service, the URL must"
                    " start with 'https://' for the URL. Failed to parse"
                    " status code from server response. Error was %s")
                    % e)
            except socket.error as se:
                error_code = se.errno
                error_msg = se.strerror
                composite_msg = _("Socket error No. %(code)s (%(msg)s) "
                                  "connecting to API with") % {
                                      'code': (six.text_type(error_code)),
                                      'msg': error_msg}
                if self._fail_fast:
                    raise exception.QBException(composite_msg)
                else:
                    LOG.warning(composite_msg)
            except http_client.HTTPException as e:
                with excutils.save_and_reraise_exception() as ctxt:
                    if self._fail_fast:
                        ctxt.reraise = True
                    else:
                        LOG.warning(_LW("Encountered error, retrying: %s"),
                                    six.text_type(e))
                        ctxt.reraise = False

        raise exception.QBException("Unable to connect to backend after "
                                    "%s retries" %
                                    six.text_type(CONNECTION_RETRIES))

    def _throw_on_http_error(self, response):
        if response.status == 401:
            raise exception.QBException(
                _("JSON RPC failed: unauthorized user %(status)s %(reason)s"
                  " Please check the Quobyte API service log for "
                  "more details.")
                % {'status': six.text_type(response.status),
                   'reason': response.reason})
        elif response.status >= 300:
            raise exception.QBException(
                _("JSON RPC failed:  %(status)s %(reason)s"
                  " Please check the Quobyte API service log for "
                  "more details.")
                % {'status': six.text_type(response.status),
                   'reason': response.reason})

    def _checked_for_application_error(self, result):
        if 'error' in result and result['error']:
            if 'message' in result['error'] and 'code' in result['error']:
                if result["error"]["code"] == ERROR_ENOENT:
                    return None  # No Entry
                else:
                    raise exception.QBRpcException(
                        result=result["error"]["message"],
                        qbcode=result["error"]["code"])
            else:
                raise exception.QBException(six.text_type(result["error"]))
        return result["result"]
