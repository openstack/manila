# Copyright (c) 2015 Mirantis, Inc.
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

"""LXC/LXD Driver for shares.

This driver allows to use a LXD container as a share server.
Current implementation suggests that a container when started by LXD will be
plugged into a Linux bridge. Also it is suggested that all interfaces willing
to talk to each other reside in an OVS bridge."""

import os
import re

from oslo_config import cfg
from oslo_log import log
from pylxd import api as lxd_api
from pylxd import exceptions as pylxd_exc
import six

from manila.common import constants as const
from manila import context
from manila import exception
from manila.i18n import _
from manila.i18n import _LW
from manila.share import driver
from manila import utils

CONF = cfg.CONF
LOG = log.getLogger(__name__)

lxd_opts = [
    # (aovchinnikov): this has to stay till we can produce images which
    # can set up OVS correctly.
    cfg.StrOpt("lxd_linux_bridge_name",
               default="lxcbr0",
               required=True,
               help="Linux bridge used by LXD to plug host-side veth to. "
                    "It will be unplugged from here by the driver."),
    cfg.StrOpt("lxd_ovs_bridge_name",
               default="br-int",
               required=True,
               help="OVS bridge to use to plug a container to."),
    cfg.StrOpt("lxd_nfs_server",
               default="unfs3",
               help="User space NFS server to be used. Currently the only "
                    "implementation supported is unfs3. In future ganesha "
                    "is planned to be supported as well. Please note, that "
                    "unfs3 is mostly an experimental driver which should "
                    "be used in production with care and at the user's own "
                    "risk."),
    cfg.IntOpt("lxd_build_timeout",
               default=120,
               help="Time to wait till container is considered being unable "
                    "to start."),
    cfg.IntOpt("lxd_check_timeout",
               default=1,
               help="Inter-check delay for container operations."),
    cfg.StrOpt("lxd_cifs_guest_ok",
               default="yes",
               help="Determines whether to allow guest access to CIFS share "
                    "or not."),
    cfg.StrOpt("lxd_image_name",
               default="manila-lxd-image",
               help="LXD image to be used for a server."),
]

lv_opts = [
    cfg.StrOpt("lxd_volume_group",
               default="manila_lxd_volumes",
               help="LVM volume group to use for volumes."),
    cfg.StrOpt("lxd_lv_size",
               default="10M",
               help="Logical volume size."),
]

CONF.register_opts(lxd_opts)
CONF.register_opts(lv_opts)


class LXDHelper(object):

    def __init__(self, lxd_api, config):
        super(LXDHelper, self).__init__()
        self.api = lxd_api
        self.conf = config

    def create_container(self, name):
        container_config = {
            "name": name,
            "source": {
                "type": "image",
                "alias": self.conf.lxd_image_name
            }
        }

        state, data = self.api.container_init(container_config)

        LOG.debug("Container init result: %s, %s.", state, data)
        LOG.debug("Containers list %s.", self.api.container_list())

        def container_initialized():
            try:
                LOG.debug("Operation 'initialize': %s.", data["operation"])
                state, info = self.api.operation_info(data["operation"])

                LOG.debug("Operation 'initialize' info: %s, %s.", state, info)

                return info["status"].lower() == "success"

            except Exception as e:
                LOG.debug("Check error '%s'.", e)
                return False

        self._wait(
            container_initialized,
            exception.ManilaException(_("Container creation error."))
        )

    @utils.retry(exception.ManilaException, retries=5)
    def start_container(self, name):
        LOG.debug("Starting container %s.", name)

        throwaway, data = self.api.container_start(name, -1)

        def container_running():
            LOG.debug("Operation 'start': %s.", data["operation"])

            try:
                state, info = self.api.operation_info(data["operation"])
            except Exception as e:
                raise exception.ManilaException(
                    _("Cannot get operation info: %s.") % e
                )

            LOG.debug("Operation 'start' info: %s, %s.", state, info)

            if "status" in info["metadata"]:
                meta = info["metadata"]
                operation_failed = (
                    six.text_type(meta["status"]).lower() == "failure" and
                    six.text_type(meta["err"]).lower() !=
                    "the container is already running"
                )
            else:
                operation_failed = False

            if operation_failed:
                err_info = info["metadata"]["metadata"]

                raise exception.ManilaException(
                    _("Cannot start container: %s.") % err_info
                )

            result = self.api.container_running(name)
            LOG.debug("Check is container running: %s.", result)
            return result

        self._wait(
            container_running,
            exception.ManilaException("Container startup error.")
        )

    def stop_container(self, name):
        LOG.debug("Stopping container %s.", name)
        state, data = self.api.container_stop(name, 60)

        def container_stopped():
            return not self.api.container_running(name)

        self._wait(
            container_stopped,
            exception.ManilaException(_("Container stopping error."))
        )
        self.api.container_destroy(name)

    def _wait(self, predicate, timeout_exception):
        utils.wait_until_true(
            predicate,
            timeout=self.conf.lxd_build_timeout,
            sleep=self.conf.lxd_check_timeout,
            exception=timeout_exception
        )

    def _wait_operation(self, operation):
        def wait():
            LOG.debug("Wait operation %s...", operation)
            try:
                state, info = self.api.operation_info(operation)
                LOG.debug("Operation details: %s.", info)
            except pylxd_exc.APIError as e:
                LOG.exception(e)
                return True
            except Exception as e:
                LOG.exception(e)
                raise exception.ManilaException(
                    _("Cannot get operation info: %s.") % e
                )

            return (
                six.text_type(info["metadata"]["status"]).lower() != "running"
            )
        self._wait(
            wait,
            exception.ManilaException(_("Operation %s still running.") %
                                      operation)
        )

    def execute_sync(self, container_name, args):
        status, result = self.api.container_run_command(
            container_name, args, interactive=True, web_sockets=True)

        LOG.debug("CMD: %s", args)
        LOG.debug("Execution result: %s", result)

        try:
            socket_pass = result["metadata"]["metadata"]["fds"]["0"]
        except KeyError:
            raise exception.ManilaException(
                _("Socket secret not found in operation details.")
            )

        stream = self.api.operation_stream(result["operation"], socket_pass)
        cmd_result = ""

        while True:
            message = stream.receive()

            if not message:
                break
            cmd_result += message.data.decode("utf-8")

            LOG.debug("CMD output: %s", cmd_result)

        # NOTE(u_glide): Since LXD >= 0.24 socket should be closed by client
        # Fix in PyLXD: https://github.com/lxc/pylxd/pull/51
        stream.close()

        status, info = self.api.operation_info(result["operation"])

        LOG.debug("Operation details: %(info)s, %(status)s.",
                  {"info": info, "status": status})
        return cmd_result


class LXDUnfs3Helper(object):
    # NOTE(aovchinnikov): This is a temporary replacement for nfs-ganesha
    # designed for testing purposes. It is not intended to be used in
    # production.
    def __init__(self, lxd_helper, *args, **kwargs):
        super(LXDUnfs3Helper, self).__init__()
        self.share = None or kwargs.get("share")
        self.lxd = lxd_helper
        self.access_rules_ro = "(ro,no_root_squash,async,no_subtree_check)"
        self.access_rules_rw = "(rw,no_root_squash,async,no_subtree_check)"

    def _restart_unfsd(self, server_id):
        LOG.debug("Restarting unfsd....")
        self.lxd.execute_sync(
            server_id,
            ["pkill", "unfsd"]
        )
        self.lxd.execute_sync(
            server_id,
            ["service", "unfs3", "start"]
        )
        LOG.debug("Restarting unfsd - done!")

    def create_share(self, server_id):
        # (aovchinnikov): the moment a folder appears in /etc/exports it could
        # have accessed with ro from anywhere. Thus create_share does
        # essentially nothing.
        self.lxd.execute_sync(
            server_id,
            ["touch", "/etc/exports"]
        )
        result = self.lxd.execute_sync(
            server_id,
            ["ip", "addr", "show", "eth0"]
        ).split()[18].split('/')[0]
        location = result + ':' + "/shares/%s" % self.share.share_id
        return location

    def delete_share(self, server_id):
        share_name = self.share.share_id
        share_folder = "/shares/%s" % share_name
        delete_pattern = "\$" + share_folder + ".*$d"
        self.lxd.execute_sync(
            server_id,
            ["sed", "-i", delete_pattern, "/etc/exports"]
        )
        self._restart_unfsd(server_id)

    def _deny_access(self, server_id, host_to_deny):
        share_name = self.share.share_id
        share_folder = "/shares/%s" % share_name
        deny_pattern = ("\$" + share_folder + '.*' +
                        host_to_deny.replace('.', '\.') + '.*$d')
        self.lxd.execute_sync(
            server_id,
            ["sed", "-i", deny_pattern, "/etc/exports"]
        )
        self._restart_unfsd(server_id)

    def _allow_access(self, share_name, server_id, host_to_allow,
                      access_level):
        if access_level == const.ACCESS_LEVEL_RO:
            access_rules = self.access_rules_ro
        elif access_level == const.ACCESS_LEVEL_RW:
            access_rules = self.access_rules_rw
        else:
            raise exception.InvalidShareAccessLevel(level=access_level)
        share_name = self.share.share_id
        share_folder = "/shares/%s" % share_name
        search_pattern = (share_folder + '.*' +
                          host_to_allow.replace('.', '\.') + '.*')
        result = self.lxd.execute_sync(
            server_id,
            ["grep", search_pattern, "/etc/exports"]
        )

        if result == '':
            new_share = share_folder + ' ' + host_to_allow + access_rules
            result = self.lxd.execute_sync(
                server_id,
                ["sed", "-i", "$ a\\" + new_share, "/etc/exports"]
            )

            self._restart_unfsd(server_id)

    def update_access(self, share_name, server_id, access_rules, add_rules,
                      delete_rules):
        if not (add_rules or delete_rules):
            share_folder = "/shares/%s" % share_name
            delete_pattern = "\$" + share_folder + ".*$d"
            self.lxd.execute_sync(
                server_id,
                ["sed", "-i", delete_pattern, "/etc/exports"]
            )
            for rule in (access_rules or []):
                host_to_allow = rule['access_to']
                access_level = rule['access_level']
                access_type = rule['access_type']
                if access_type == 'ip':
                    self._allow_access(share_name, server_id, host_to_allow,
                                       access_level)
                else:
                    msg = _("Access type '%s' is not supported by the "
                            "driver.") % access_type
                    raise exception.InvalidShareAccess(reason=msg)
            return
        for rule in add_rules:
            host_to_allow = rule['access_to']
            access_level = rule['access_level']
            access_type = rule['access_type']
            if access_type == 'ip':
                self._allow_access(share_name, server_id, host_to_allow,
                                   access_level)
            else:
                msg = _("Access type '%s' is not supported by the "
                        "driver.") % access_type
                raise exception.InvalidShareAccess(reason=msg)
        for rule in delete_rules:
            host_to_deny = rule['access_to']
            access_type = rule['access_type']
            if access_type == 'ip':
                self._deny_access(server_id, host_to_deny)
            else:
                LOG.warning(_LW("Attempt to use access type %s has been "
                                "blocked.") % access_type)


class LXDCIFSHelper(object):
    def __init__(self, lxd_helper, *args, **kwargs):
        super(LXDCIFSHelper, self).__init__()
        self.share = None or kwargs.get("share")
        self.conf = kwargs.get("config")
        self.lxd = lxd_helper

    def create_share(self, server_id):
        share_name = self.share.share_id
        cmd = ["net", "conf", "addshare", share_name,
               "/shares/%s" % share_name, "writeable=y"]
        if self.conf.lxd_cifs_guest_ok == "yes":
            cmd.append("guest_ok=y")
        else:
            cmd.append("guest_ok=n")
        self.lxd.execute_sync(server_id, cmd)
        parameters = {
            "browseable": "yes",
            "create mask": "0755",
            "hosts deny": "0.0.0.0/0",
            "hosts allow": "127.0.0.1",
            "read only": "no",
        }
        for param, value in parameters.items():
            self.lxd.execute_sync(
                server_id,
                ["net", "conf", "setparm", share_name, param, value]
            )
        result = self.lxd.execute_sync(
            server_id,
            ["ip", "addr", "show", "eth0"]
        ).split()[18].split('/')[0]
        location = '\\\\' + result + '\\' + "/shares/%s" % share_name
        return location

    def delete_share(self, server_id):
        self.lxd.execute_sync(
            server_id,
            ["net", "conf", "delshare", self.share.share_id]
        )

    def _deny_access(self, server_id, host_to_deny):
        share_name = self.share.share_id
        allowed_hosts = self.lxd.execute_sync(
            server_id,
            ["net", "conf", "getparm", share_name, "hosts allow"]
        )
        if allowed_hosts.count(host_to_deny) == 0:
            LOG.debug("Access for host %s is already denied.", host_to_deny)
            return
        pruned_hosts = filter(lambda x: not x.startswith(host_to_deny),
                              allowed_hosts.split())
        allowed_hosts = " ".join(pruned_hosts)
        self.lxd.execute_sync(
            server_id,
            ["net", "conf", "setparm", share_name, "hosts allow",
             allowed_hosts]
        )

    def _allow_access(self, share_name, server_id, host_to_allow,
                      access_level):
        if access_level == const.ACCESS_LEVEL_RO:
            if self.conf.lxd_cifs_guest_ok != "yes":
                raise exception.ManilaException(_("Can't provide 'ro' access"
                                                  "for guest."))
            LOG.debug("Host is accessible for reading data.")
            return
        elif access_level == const.ACCESS_LEVEL_RW:
            allowed_hosts = self.lxd.execute_sync(
                server_id,
                ["net", "conf", "getparm", share_name, "hosts allow"]
            )
            if allowed_hosts.count(host_to_allow) != 0:
                LOG.debug("Access for host %s is already allowed.",
                          host_to_allow)
                return

            allowed_hosts = ", ".join([host_to_allow, allowed_hosts])
            self.lxd.execute_sync(
                server_id,
                ["net", "conf", "setparm", share_name, "hosts allow",
                 allowed_hosts]
            )
        else:
            raise exception.InvalidShareAccessLevel(level=access_level)

    def _allow_user_access(self, share_name, server_id, user_to_allow,
                           access_level):
        if access_level == const.ACCESS_LEVEL_RO:
            access = 'read list'
        elif access_level == const.ACCESS_LEVEL_RW:
            access = 'valid users'
        else:
            raise exception.InvalidShareAccessLevel(level=access_level)
        self.lxd.execute_sync(
            server_id,
            ["net", "conf", "setparm", share_name, access,
             user_to_allow]
        )

    def update_access(self, share_name, server_id, access_rules,
                      add_rules=None, delete_rules=None):
        if not (add_rules or delete_rules):
            # clean all hosts from allowed hosts list first.
            self.lxd.execute_sync(
                server_id,
                ["net", "conf", "setparm", share_name, "hosts allow", ""]
            )
            for rule in (access_rules or []):
                host_to_allow = rule['access_to']
                access_level = rule['access_level']
                access_type = rule['access_type']
                if access_type == 'ip':
                    self._allow_access(share_name, server_id, host_to_allow,
                                       access_level)
                elif access_type == 'user':
                    self._allow_user_access(share_name, server_id,
                                            rule['access_to'], access_level)
                else:
                    msg = _("Access type '%s' is not supported by the "
                            "driver.") % access_type
                    raise exception.InvalidShareAccess(reason=msg)
            return
        for rule in add_rules:
            host_to_allow = rule['access_to']
            access_level = rule['access_level']
            access_type = rule['access_type']
            if access_type == 'ip':
                self._allow_access(share_name, server_id, host_to_allow,
                                   access_level)
            elif access_type == 'user':
                self._allow_user_access(share_name, server_id,
                                        rule['access_to'], access_level)
            else:
                msg = _("Access type '%s' is not supported by the "
                        "driver.") % access_type
                raise exception.InvalidShareAccess(reason=msg)
        for rule in delete_rules:
            host_to_deny = rule['access_to']
            access_type = rule['access_type']
            if access_type == 'ip':
                self._deny_access(server_id, host_to_deny)
            else:
                LOG.warning(_LW("Attempt to use access type %s has been "
                                "blocked.") % access_type)


class LXDDriver(driver.GaneshaMixin, driver.ShareDriver, driver.ExecuteMixin):
    """Executes commands relating to Shares."""

    def __init__(self, *args, **kwargs):
        """Do initialization."""
        super(LXDDriver, self).__init__([True], *args, **kwargs)

        self.admin_context = context.get_admin_context()
        self.configuration.append_config_values(lxd_opts)
        self.configuration.append_config_values(lv_opts)
        self._helpers = {}
        self.backend_name = self.configuration.safe_get(
            "share_backend_name") or "LXD"
        self.private_storage = kwargs.get("private_storage")
        # TODO(uglide): add config options for LXD host and port
        # TODO(uglide): raise specific exception on timeout
        self.lxd = LXDHelper(lxd_api.API(), self.configuration)
        self.ssh_connections = {}
        self.nfshelper = self._get_nfs_helper()

    def _update_share_stats(self):
        """Retrieve stats info from share volume group."""
        data = {
            'share_backend_name': self.backend_name,
            'storage_protocol': 'NFS_CIFS',
            'reserved_percentage':
                self.configuration.reserved_share_percentage,
            'consistency_group_support': None,
            'snapshot_support': False,
            'driver_name': 'LXDDriver',
            'pools': self.get_share_server_pools()
        }
        super(LXDDriver, self)._update_share_stats(data)

    def get_share_server_pools(self, share_server=None):
        out, err = self._execute('vgs',
                                 self.configuration.lxd_volume_group,
                                 '--rows', run_as_root=True)
        total_size = re.findall("VSize\s[0-9.]+g", out)[0][6:-1]
        free_size = re.findall("VFree\s[0-9.]+g", out)[0][6:-1]
        return [{
            'pool_name': self.configuration.lxd_volume_group,
            'total_capacity_gb': float(total_size),
            'free_capacity_gb': float(free_size),
            'reserved_percentage': 0,
        }, ]

    def _get_nfs_helper(self):
        if self.configuration.lxd_nfs_server == 'ganesha':
            raise exception.ManilaException(_("NFSGanesha is currently not "
                                              "supported by this driver."))
        elif self.configuration.lxd_nfs_server == 'unfs3':
            return LXDUnfs3Helper
        else:
            raise exception.ManilaException(_("Unsupported NFS userspace "
                                              "server: %s.") %
                                            self.configuration.lxd_nfs_server)

    def _get_helper(self, share):
        if share["share_proto"].upper() == "NFS":
            helper = self._helpers.get("NFS")
            if helper is not None:
                helper.share = share
                return helper
            self._helpers["NFS"] = self.nfshelper(self.lxd, share=share)
            return self._helpers["NFS"]
        elif share["share_proto"].upper() == "CIFS":
            helper = self._helpers.get("CIFS")
            if helper is not None:
                helper.share = share
                return helper
            self._helpers["CIFS"] = LXDCIFSHelper(self.lxd, share=share,
                                                  config=self.configuration)
            return self._helpers["CIFS"]
        else:
            raise exception.InvalidShare(
                reason=_("Wrong, unsupported or disabled protocol."))

    def _get_lv_device(self, share):
        return os.path.join("/dev", self.configuration.lxd_volume_group,
                            share.share_id)

    def _get_lv_folder(self, share):
        # Provides folder name in hosts /tmp to which logical volume is
        # mounted prior to providing access to it from a container.
        return os.path.join("/tmp", share.share_id)

    def create_share(self, context, share, share_server=None):
        LOG.debug("Create share on server '%s'." % share_server["id"])
        server_id = self._get_container_name(share_server["id"])
        share_name = share.share_id
        self.lxd.execute_sync(
            server_id,
            ["mkdir", "-m", "777", "/shares/%s" % share_name]
        )
        self._execute("lvcreate", "-p", "rw", "-L",
                      self.configuration.lxd_lv_size, "-n", share_name,
                      self.configuration.lxd_volume_group, run_as_root=True)
        self._execute("mkfs.ext4", self._get_lv_device(share),
                      run_as_root=True)
        self._execute("mkdir", "-m", "777", self._get_lv_folder(share))
        self._execute("mount", self._get_lv_device(share),
                      self._get_lv_folder(share), run_as_root=True)
        self._execute("chmod", "-R", "777", self._get_lv_folder(share),
                      run_as_root=True)
        self._execute("lxc", "config", "device", "add",
                      server_id, share_name, "disk",
                      "source=" + self._get_lv_folder(share),
                      "path=/shares/" + share_name, run_as_root=True)

        location = self._get_helper(share).create_share(server_id)
        return location

    def extend_share(self, share, new_size, share_server=None):
        lv_device = self._get_lv_device(share)
        cmd = ('lvextend', '-L', '%sG' % new_size, '-n', lv_device)
        self._execute(*cmd, run_as_root=True)
        self._execute('resize2fs', lv_device, run_as_root=True)

    def _connect_to_network(self, server_id, network_info):
        LOG.debug("Attempting to connect container to neutron network.")
        network_allocation = network_info['network_allocations'][0]
        port_address = network_allocation.ip_address
        port_mac = network_allocation.mac_address
        port_id = network_allocation.id
        self.lxd.execute_sync(
            server_id,
            ["ifconfig", "eth0", port_address, "up"]
        )
        host_veth = self._get_host_veth(server_id)
        msg_helper = {
            'id': server_id, 'veth': host_veth,
            'lb': self.configuration.lxd_linux_bridge_name,
            'ovsb': self.configuration.lxd_ovs_bridge_name,
            'ip': port_address,
            'subnet': network_info['neutron_subnet_id']
        }
        LOG.debug("Container %(id)s veth is %(veth)s.", msg_helper)
        LOG.debug("Removing %(veth)s from %(lb)s.", msg_helper)
        self._execute("brctl", "delif",
                      self.configuration.lxd_linux_bridge_name, host_veth,
                      run_as_root=True)

        LOG.debug("Plugging %(veth)s into %(ovsb)s.", msg_helper)
        set_if = ['--', 'set', 'interface', host_veth]
        e_mac = set_if + ['external-ids:attached-mac="%s"' % port_mac]
        e_id = set_if + ['external-ids:iface-id="%s"' % port_id]
        e_status = set_if + ['external-ids:iface-status=active']
        self._execute("ovs-vsctl", "--", "add-port",
                      self.configuration.lxd_ovs_bridge_name, host_veth,
                      *(e_mac + e_id + e_status), run_as_root=True)
        LOG.debug("Now container %(id)s should be accessible from network "
                  "%(subnet)s by address %(ip)s." % msg_helper)

    def delete_share(self, context, share, share_server=None):
        LOG.debug("Deleting share %(share)s on server '%(server)s'." %
                  {"server": share_server["id"],
                   "share": share.share_id})
        server_id = self._get_container_name(share_server["id"])
        self._get_helper(share).delete_share(server_id)

        self._execute("umount", self._get_lv_device(share), run_as_root=True)
        self._execute("lxc", "config", "device", "remove",
                      server_id, share.share_id, run_as_root=True)
        self._execute("lvremove", "-f", "--autobackup", "n",
                      self._get_lv_device(share), run_as_root=True)
        self.lxd.execute_sync(
            server_id,
            ["rm", "-fR", "/shares/%s" % share.share_id]
        )
        LOG.debug("Deletion of share %s is complete!", share.share_id)

    def _get_host_veth(self, server_id):
        data = self.lxd.api.container_info(server_id)
        host_veth = data['network']['eth0']['host_name']
        return host_veth

    def _teardown_server(self, *args, **kwargs):
        server_id = self._get_container_name(kwargs["server_details"]["id"])
        host_veth = self._get_host_veth(server_id)
        self.lxd.stop_container(server_id)
        self._execute("ovs-vsctl", "--", "del-port",
                      self.configuration.lxd_ovs_bridge_name, host_veth,
                      run_as_root=True)

    def ensure_share(self, context, share, share_server=None):
        pass

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        server_id = self._get_container_name(share_server["id"])
        share_name = share.share_id
        LOG.debug("Updating access to share %(share)s at "
                  "share server %(share_server)s.",
                  {"share_server": share_server["id"],
                   "share": share.share_id})
        self._get_helper(share).update_access(share_name, server_id,
                                              access_rules, add_rules,
                                              delete_rules)

    def get_network_allocations_number(self):
        return 1

    def _get_container_name(self, server_id):
        return "manila-%s" % server_id

    def _setup_server(self, network_info, metadata=None):
        msg = "Creating share server '%s'."
        server_id = self._get_container_name(network_info["server_id"])
        LOG.debug(msg % server_id)

        try:
            self.lxd.create_container(server_id)
        except Exception as e:
            raise exception.ManilaException(_("Cannot create container: %s") %
                                            e)

        self.lxd.start_container(server_id)
        self.lxd.api.container_run_command(server_id,
                                           ["mkdir", "-m", "777", "/shares"])
        self._connect_to_network(server_id, network_info)
        # TODO(aovchinnikov): expand metadata above the bare minimum
        LOG.debug("Container %s was created!", server_id)
        return {"id": network_info["server_id"]}
