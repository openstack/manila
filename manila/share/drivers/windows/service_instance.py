# Copyright (c) 2015 Cloudbase Solutions SRL
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

import os
import re

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log

from manila import exception
from manila.i18n import _, _LI, _LW
from manila.share.drivers import service_instance
from manila.share.drivers.windows import windows_utils
from manila.share.drivers.windows import winrm_helper


CONF = cfg.CONF
LOG = log.getLogger(__name__)

windows_share_server_opts = [
    cfg.StrOpt(
        "winrm_cert_pem_path",
        default="~/.ssl/cert.pem",
        help="Path to the x509 certificate used for accessing the service"
             "instance."),
    cfg.StrOpt(
        "winrm_cert_key_pem_path",
        default="~/.ssl/key.pem",
        help="Path to the x509 certificate key."),
    cfg.BoolOpt(
        "winrm_use_cert_based_auth",
        default=False,
        help="Use x509 certificates in order to authenticate to the"
             "service instance.")
]

CONF = cfg.CONF
CONF.register_opts(windows_share_server_opts)


class WindowsServiceInstanceManager(service_instance.ServiceInstanceManager):
    """"Manages Windows Nova instances."""
    _INSTANCE_CONNECTION_PROTO = "WinRM"
    _CBS_INIT_RUN_PLUGIN_AFTER_REBOOT = 2
    _CBS_INIT_WINRM_PLUGIN = "ConfigWinRMListenerPlugin"
    _DEFAULT_MINIMUM_PASS_LENGTH = 6

    def __init__(self, driver_config=None, remote_execute=None):
        super(WindowsServiceInstanceManager, self).__init__(
            driver_config=driver_config)
        driver_config.append_config_values(windows_share_server_opts)

        self._use_cert_auth = self.get_config_option(
            "winrm_use_cert_based_auth")
        self._cert_pem_path = self.get_config_option(
            "winrm_cert_pem_path")
        self._cert_key_pem_path = self.get_config_option(
            "winrm_cert_key_pem_path")
        self._check_auth_mode()

        self._remote_execute = (remote_execute or
                                winrm_helper.WinRMHelper(
                                    configuration=driver_config).execute)
        self._windows_utils = windows_utils.WindowsUtils(
            remote_execute=self._remote_execute)

    def _check_auth_mode(self):
        if self._use_cert_auth:
            if not (os.path.exists(self._cert_pem_path) and
                    os.path.exists(self._cert_key_pem_path)):
                msg = _("Certificate based authentication was configured "
                        "but one or more certificates are missing.")
                raise exception.ServiceInstanceException(msg)
            LOG.debug("Using certificate based authentication for "
                      "service instances.")
        else:
            instance_password = self.get_config_option(
                "service_instance_password")
            if not self._check_password_complexity(instance_password):
                msg = _("The configured service instance password does not "
                        "match the minimum complexity requirements. "
                        "The password must contain at least %s characters. "
                        "Also, it must contain at least one digit, "
                        "one lower case and one upper case character.")
                raise exception.ServiceInstanceException(
                    msg % self._DEFAULT_MINIMUM_PASS_LENGTH)
            LOG.debug("Using password based authentication for "
                      "service instances.")

    def _get_auth_info(self):
        auth_info = {'use_cert_auth': self._use_cert_auth}
        if self._use_cert_auth:
            auth_info.update(cert_pem_path=self._cert_pem_path,
                             cert_key_pem_path=self._cert_key_pem_path)
        return auth_info

    def get_common_server(self):
        data = super(WindowsServiceInstanceManager, self).get_common_server()
        data['backend_details'].update(self._get_auth_info())
        return data

    def _get_new_instance_details(self, server):
        instance_details = super(WindowsServiceInstanceManager,
                                 self)._get_new_instance_details(server)
        instance_details.update(self._get_auth_info())
        return instance_details

    def _check_password_complexity(self, password):
        # Make sure that the Windows complexity requirements are met:
        # http://technet.microsoft.com/en-us/library/cc786468(v=ws.10).aspx
        if len(password) < self._DEFAULT_MINIMUM_PASS_LENGTH:
            return False
        for r in ("[a-z]", "[A-Z]", "[0-9]"):
            if not re.search(r, password):
                return False
        return True

    def _test_server_connection(self, server):
        try:
            self._remote_execute(server, "whoami", retry=False)
            LOG.debug("Service VM %s is available via WinRM",
                      server['ip'])
            return True
        except Exception as ex:
            LOG.debug("Server %(ip)s is not available via WinRM. "
                      "Exception: %(ex)s ",
                      dict(ip=server['ip'],
                           ex=ex))
            return False

    def _get_service_instance_create_kwargs(self):
        create_kwargs = {}
        if self._use_cert_auth:
            # At the moment, we pass the x509 certificate via user data.
            # We'll use keypairs instead as soon as the nova client will
            # support x509 certificates.
            with open(self._cert_pem_path, 'r') as f:
                cert_pem_data = f.read()
            create_kwargs['user_data'] = cert_pem_data
        else:
            # The admin password has to be specified via instance metadata in
            # order to be passed to the instance via the metadata service or
            # configdrive.
            admin_pass = self.get_config_option("service_instance_password")
            create_kwargs['meta'] = {'admin_pass': admin_pass}
        return create_kwargs

    def set_up_service_instance(self, context, network_info):
        instance_details = super(WindowsServiceInstanceManager,
                                 self).set_up_service_instance(context,
                                                               network_info)
        security_services = network_info['security_services']
        security_service = self.get_valid_security_service(security_services)
        if security_service:
            self._setup_security_service(instance_details, security_service)

        instance_details['joined_domain'] = bool(security_service)
        return instance_details

    def _setup_security_service(self, server, security_service):
        domain = security_service['domain']
        admin_username = security_service['user']
        admin_password = security_service['password']
        dns_ip = security_service['dns_ip']

        self._windows_utils.set_dns_client_search_list(server, [domain])

        if_index = self._windows_utils.get_interface_index_by_ip(server,
                                                                 server['ip'])
        self._windows_utils.set_dns_client_server_addresses(server,
                                                            if_index,
                                                            [dns_ip])
        # Joining an AD domain will alter the WinRM Listener configuration.
        # Cloudbase-init is required to be running on the Windows service
        # instance, so we re-enable the plugin configuring the WinRM listener.
        #
        # TODO(lpetrut): add a config option so that we may rely on the AD
        # group policies taking care of the WinRM configuration.
        self._run_cloudbase_init_plugin_after_reboot(
            server, plugin_name=self._CBS_INIT_WINRM_PLUGIN)
        self._join_domain(server, domain, admin_username, admin_password)

    def _join_domain(self, server, domain, admin_username, admin_password):
        # As the WinRM configuration may be altered and existing connections
        # closed, we may not be able to retrieve the result of this operation.
        # Instead, we'll ensure that the instance actually joined the domain
        # after the reboot.
        try:
            self._windows_utils.join_domain(server, domain, admin_username,
                                            admin_password)
        except processutils.ProcessExecutionError:
            raise
        except Exception as exc:
            LOG.debug("Unexpected error while attempting to join domain "
                      "%(domain)s. Verifying the result of the operation "
                      "after instance reboot. Exception: %(exc)s",
                      dict(domain=domain, exc=exc))
        # We reboot the service instance using the Compute API so that
        # we can wait for it to become active.
        self.reboot_server(server, soft_reboot=True)
        self.wait_for_instance_to_be_active(
            server['instance_id'],
            timeout=self.max_time_to_build_instance)
        if not self._check_server_availability(server):
            raise exception.ServiceInstanceException(
                _('%(conn_proto)s connection has not been '
                  'established to %(server)s in %(time)ss. Giving up.') % {
                      'conn_proto': self._INSTANCE_CONNECTION_PROTO,
                      'server': server['ip'],
                      'time': self.max_time_to_build_instance})

        current_domain = self._windows_utils.get_current_domain(server)
        if current_domain != domain:
            err_msg = _("Failed to join domain %(requested_domain)s. "
                        "Current domain: %(current_domain)s")
            raise exception.ServiceInstanceException(
                err_msg % dict(requested_domain=domain,
                               current_domain=current_domain))

    def get_valid_security_service(self, security_services):
        if not security_services:
            LOG.info(_LI("No security services provided."))
        elif len(security_services) > 1:
            LOG.warning(_LW("Multiple security services provided. Only one "
                            "security service of type 'active_directory' "
                            "is supported."))
        else:
            security_service = security_services[0]
            security_service_type = security_service['type']
            if security_service_type == 'active_directory':
                return security_service
            else:
                LOG.warning(_LW("Only security services of type "
                                "'active_directory' are supported. "
                                "Retrieved security "
                                "service type: %(sec_type)s."),
                            {'sec_type': security_service_type})
        return None

    def _run_cloudbase_init_plugin_after_reboot(self, server, plugin_name):
        cbs_init_reg_section = self._get_cbs_init_reg_section(server)
        plugin_key_path = "%(cbs_init_section)s\\%(instance_id)s\\Plugins" % {
            'cbs_init_section': cbs_init_reg_section,
            'instance_id': server['instance_id']
        }
        self._windows_utils.set_win_reg_value(
            server, path=plugin_key_path, key=plugin_name,
            value=self._CBS_INIT_RUN_PLUGIN_AFTER_REBOOT)

    def _get_cbs_init_reg_section(self, server):
        base_path = 'hklm:\\SOFTWARE'
        cbs_section = 'Cloudbase Solutions\\Cloudbase-Init'

        for upper_section in ('', 'Wow6432Node'):
            cbs_init_section = self._windows_utils.normalize_path(
                os.path.join(base_path, upper_section, cbs_section))
            try:
                self._windows_utils.get_win_reg_value(
                    server, path=cbs_init_section)
                return cbs_init_section
            except processutils.ProcessExecutionError as ex:
                # The exit code will always be '1' in case of errors, so the
                # only way to determine the error type is checking stderr.
                if 'Cannot find path' in ex.stderr:
                    continue
                else:
                    raise
        raise exception.ServiceInstanceException(
            _("Could not retrieve Cloudbase Init registry section"))
