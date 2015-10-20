# Copyright (c) 2015 EMC Corporation.
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

import pipes

from oslo_concurrency import processutils
from oslo_log import log
from oslo_utils import excutils
import six
from six.moves import http_cookiejar
from six.moves.urllib import error as url_error  # pylint: disable=E0611
from six.moves.urllib import request as url_request  # pylint: disable=E0611

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.share.drivers.emc.plugins.vnx import constants
from manila import utils

LOG = log.getLogger(__name__)


class XMLAPIConnector(object):
    def __init__(self, configuration, debug=True):
        super(XMLAPIConnector, self).__init__()
        self.storage_ip = configuration.emc_nas_server
        self.username = configuration.emc_nas_login
        self.password = configuration.emc_nas_password
        self.debug = debug
        self.auth_url = 'https://' + self.storage_ip + '/Login'
        self._url = ('https://' + self.storage_ip
                     + '/servlets/CelerraManagementServices')
        https_handler = url_request.HTTPSHandler()
        cookie_handler = url_request.HTTPCookieProcessor(
            http_cookiejar.CookieJar())
        self.url_opener = url_request.build_opener(https_handler,
                                                   cookie_handler)
        self._do_setup()

    def _do_setup(self):
        credential = ('user=' + self.username
                      + '&password=' + self.password
                      + '&Login=Login')
        req = url_request.Request(self.auth_url, credential,
                                  constants.CONTENT_TYPE_URLENCODE)
        resp = self.url_opener.open(req)
        resp_body = resp.read()
        self._http_log_resp(resp, resp_body)

    def _http_log_req(self, req):
        if not self.debug:
            return

        string_parts = ['curl -i']
        string_parts.append(' -X %s' % req.get_method())

        for k in req.headers:
            header = ' -H "%s: %s"' % (k, req.headers[k])
            string_parts.append(header)

        if req.data:
            string_parts.append(" -d '%s'" % req.data)
        string_parts.append(' ' + req.get_full_url())
        LOG.debug("\nREQ: %s.\n", "".join(string_parts))

    def _http_log_resp(self, resp, body):
        if not self.debug:
            return

        headers = six.text_type(resp.headers).replace('\n', '\\n')

        LOG.debug(
            'RESP: [%(code)s] %(resp_hdrs)s\n'
            'RESP BODY: %(resp_b)s.\n',
            {
                'code': resp.getcode(),
                'resp_hdrs': headers,
                'resp_b': body,
            }
        )

    def _request(self, req_body=None, method=None,
                 header=constants.CONTENT_TYPE_URLENCODE):
        req = url_request.Request(self._url, req_body, header)
        if method not in (None, 'GET', 'POST'):
            req.get_method = lambda: method
        self._http_log_req(req)
        try:
            resp = self.url_opener.open(req)
            resp_body = resp.read()
            self._http_log_resp(resp, resp_body)
        except url_error.HTTPError as http_err:
            err = {'errorCode': -1,
                   'httpStatusCode': http_err.code,
                   'messages': six.text_type(http_err),
                   'request': req_body}
            msg = (_("The request is invalid. Reason: %(reason)s") %
                   {'reason': err})
            if '403' == six.text_type(http_err.code):
                raise exception.NotAuthorized()
            else:
                raise exception.ManilaException(message=msg)

        return resp_body

    def request(self, req_body=None, method=None,
                header=constants.CONTENT_TYPE_URLENCODE):
        try:
            resp_body = self._request(req_body, method, header)
        except exception.NotAuthorized:
            LOG.debug("Login again because client certification "
                      "may be expired.")
            self._do_setup()
            resp_body = self._request(req_body, method, header)

        return resp_body


class SSHConnector(object):
    def __init__(self, configuration, debug=True):
        super(SSHConnector, self).__init__()
        self.storage_ip = configuration.emc_nas_server
        self.username = configuration.emc_nas_login
        self.password = configuration.emc_nas_password
        self.debug = debug

        self.sshpool = utils.SSHPool(ip=self.storage_ip,
                                     port=22,
                                     conn_timeout=None,
                                     login=self.username,
                                     password=self.password)

    def run_ssh(self, cmd_list, check_exit_code=False):
        command = ' '.join(pipes.quote(cmd_arg) for cmd_arg in cmd_list)

        with self.sshpool.item() as ssh:
            try:
                out, err = processutils.ssh_execute(
                    ssh, command, check_exit_code=check_exit_code)
                self.log_request(command, out, err)

                return out, err
            except processutils.ProcessExecutionError as e:
                with excutils.save_and_reraise_exception():
                    msg = (_LE('Error running SSH command: %(cmd)s. '
                               'Error: %(excmsg)s.'),
                           {'cmd': command, 'excmsg': six.text_type(e)})
                    LOG.error(msg)

    def log_request(self, cmd, out, err):
        if not self.debug:
            return

        LOG.debug("\nSSH command: %s.\n", cmd)
        LOG.debug("SSH command output: out=%(out)s, err=%(err)s.\n",
                  {'out': out, 'err': err})
