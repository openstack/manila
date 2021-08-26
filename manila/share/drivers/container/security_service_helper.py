# Copyright (c) 2021 NetApp, Inc.
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


from oslo_log import log as logging

from manila import exception
from manila.i18n import _
from manila.share import driver
from manila import utils as manila_utils

# LDAP error codes
LDAP_INVALID_CREDENTIALS = 49

LOG = logging.getLogger(__name__)


class SecurityServiceHelper(driver.ExecuteMixin):
    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration", None)
        super(SecurityServiceHelper, self).__init__(*args, **kwargs)
        self.init_execute_mixin()

    def setup_security_service(self, share_server_id, security_service):
        msg = ("Setting up the security service %(service)s for share server "
               "%(server_id)s")
        msg_args = {
            'service': security_service['id'],
            'server_id': share_server_id
        }
        LOG.debug(msg, msg_args)
        self.ldap_bind(share_server_id, security_service)

    def update_security_service(self, server_id, current_security_service,
                                new_security_service):
        msg = ("Updating the security service %(service)s for share server "
               "%(server_id)s")
        msg_args = {
            'service': new_security_service['id'],
            'server_id': server_id
        }
        LOG.debug(msg, msg_args)
        self.ldap_bind(server_id, new_security_service)

    def ldap_bind(self, share_server_id, security_service):
        ss_info = self.ldap_get_info(security_service)
        cmd = ["docker", "exec", "%s" % share_server_id, "ldapwhoami", "-x",
               "-H", "ldap://localhost:389", "-D",
               "cn=%s,dc=example,dc=com" % ss_info["ss_user"], "-w", "%s" %
               ss_info["ss_password"]]
        self.ldap_retry_operation(cmd, run_as_root=True)

    def ldap_get_info(self, security_service):
        if all(info in security_service for info in ("user", "password")):
            ss_user = security_service["user"]
            ss_password = security_service["password"]
        else:
            raise exception.ShareBackendException(
                _("LDAP requires user and password to be set for the bind "
                  "operation."))
        ss_info = {
            "ss_user": ss_user,
            "ss_password": ss_password,
        }
        return ss_info

    def ldap_retry_operation(self, cmd, run_as_root=True, timeout=30):
        interval = 5
        retries = int(timeout / interval) or 1

        @manila_utils.retry(retry_param=exception.ProcessExecutionError,
                            interval=interval,
                            retries=retries, backoff_rate=1)
        def try_ldap_operation():
            try:
                self._execute(*cmd, run_as_root=run_as_root)
            except exception.ProcessExecutionError as e:
                if e.exit_code == LDAP_INVALID_CREDENTIALS:
                    msg = _('LDAP credentials are invalid. '
                            'Aborting operation.')
                    LOG.warning(msg)
                    raise exception.ShareBackendException(msg=msg)
                else:
                    msg = _('Command has returned execution error.'
                            ' Will retry the operation.'
                            ' Error details: %s') % e.stderr
                    LOG.warning(msg)
                    raise exception.ProcessExecutionError()

        try:
            try_ldap_operation()
        except exception.ProcessExecutionError as e:
            msg = _("Unable to execute LDAP operation with success. "
                    "Retries exhausted. Error details: %s") % e.stderr
            LOG.exception(msg)
            raise exception.ShareBackendException(msg=msg)
