# Copyright (c) 2016 Mirantis, Inc.
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

"""Container Driver for shares.

This driver uses a container as a share server.
Current implementation suggests that a container when started by Docker will
be plugged into a Linux bridge. Also it is suggested that all interfaces
willing to talk to each other reside in an OVS bridge."""

import math

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import uuidutils

from manila import exception
from manila.i18n import _
from manila.share import driver
from manila import utils


CONF = cfg.CONF
LOG = log.getLogger(__name__)


container_opts = [
    cfg.StrOpt("container_linux_bridge_name",
               default="docker0",
               required=True,
               help="Linux bridge used by container hypervisor to plug "
                    "host-side veth to. It will be unplugged from here "
                    "by the driver."),
    cfg.StrOpt("container_ovs_bridge_name",
               default="br-int",
               required=True,
               help="OVS bridge to use to plug a container to."),
    cfg.BoolOpt("container_cifs_guest_ok",
                default=True,
                help="Determines whether to allow guest access to CIFS share "
                     "or not."),
    cfg.StrOpt("container_image_name",
               default="manila-docker-container",
               help="Image to be used for a container-based share server."),
    cfg.StrOpt("container_helper",
               default="manila.share.drivers.container.container_helper."
               "DockerExecHelper",
               help="Container helper which provides container-related "
                    "operations to the driver."),
    cfg.StrOpt("container_protocol_helper",
               default="manila.share.drivers.container.protocol_helper."
               "DockerCIFSHelper",
               help="Helper which facilitates interaction with share server."),
    cfg.StrOpt("container_security_service_helper",
               default="manila.share.drivers.container.security_service_helper"
                       ".SecurityServiceHelper",
               help="Helper which facilitates interaction with security "
                    "services."),
    cfg.StrOpt("container_storage_helper",
               default="manila.share.drivers.container.storage_helper."
               "LVMHelper",
               help="Helper which facilitates interaction with storage "
                    "solution used to actually store data. By default LVM "
                    "is used to provide storage for a share."),
    cfg.StrOpt("container_volume_mount_path",
               default="/tmp/shares",
               help="Folder name in host to which logical volume will be "
                    "mounted prior to providing access to it from a "
                    "container."),
]


class ContainerShareDriver(driver.ShareDriver, driver.ExecuteMixin):
    def __init__(self, *args, **kwargs):
        super(ContainerShareDriver, self).__init__([True], *args, **kwargs)
        self.configuration.append_config_values(container_opts)
        self.backend_name = self.configuration.safe_get(
            "share_backend_name") or "Docker"
        self.container = importutils.import_class(
            self.configuration.container_helper)(
                configuration=self.configuration)
        self.security_service_helper = importutils.import_class(
            self.configuration.container_security_service_helper)(
                configuration=self.configuration)
        self.storage = importutils.import_class(
            self.configuration.container_storage_helper)(
                configuration=self.configuration)
        self._helpers = {}
        self.network_allocation_update_support = True

    def _get_helper(self, share):
        if share["share_proto"].upper() == "CIFS":
            helper = self._helpers.get("CIFS")
            if helper is not None:
                return helper(self.container,
                              share=share,
                              config=self.configuration)
            self._helpers["CIFS"] = importutils.import_class(
                self.configuration.container_protocol_helper)
            return self._helpers["CIFS"](self.container,
                                         share=share,
                                         config=self.configuration)
        else:
            raise exception.InvalidShare(
                reason=_("Wrong, unsupported or disabled protocol."))

    def _update_share_stats(self):
        data = {
            'share_backend_name': self.backend_name,
            'storage_protocol': 'CIFS',
            'reserved_percentage':
                self.configuration.reserved_share_percentage,
            'reserved_snapshot_percentage':
                self.configuration.reserved_share_from_snapshot_percentage or
                self.configuration.reserved_share_percentage,
            'reserved_share_extend_percentage':
                self.configuration.reserved_share_extend_percentage or
                self.configuration.reserved_share_percentage,
            'consistency_group_support': None,
            'snapshot_support': False,
            'create_share_from_snapshot_support': False,
            'driver_name': 'ContainerShareDriver',
            'pools': self.storage.get_share_server_pools(),
            'security_service_update_support': True,
            'share_server_multiple_subnet_support': True,
        }
        super(ContainerShareDriver, self)._update_share_stats(data)

    def create_share(self, context, share, share_server=None):
        LOG.debug("Create share on server '%s'.", share_server["id"])
        server_id = self._get_container_name(share_server["id"])
        share_name = share.share_id
        self.storage.provide_storage(share_name, share['size'])

        location = self._create_export_and_mount_storage(
            share, server_id, share_name)

        return location

    @utils.synchronized('container_driver_delete_share_lock', external=True)
    def delete_share(self, context, share, share_server=None):
        LOG.debug("Deleting share %(share)s on server '%(server)s'.",
                  {"server": share_server["id"],
                   "share": self._get_share_name(share)})
        server_id = self._get_container_name(share_server["id"])
        share_name = self._get_share_name(share)

        self._delete_export_and_umount_storage(share, server_id, share_name,
                                               ignore_errors=True)

        self.storage.remove_storage(share_name)
        LOG.debug("Deleted share %s successfully.", share_name)

    def _get_share_name(self, share):
        if share.get('export_location'):
            return share['export_location'].split('/')[-1]
        else:
            return share.share_id

    def extend_share(self, share, new_size, share_server=None):
        server_id = self._get_container_name(share_server["id"])
        share_name = self._get_share_name(share)
        self.container.execute(
            server_id,
            ["umount", "/shares/%s" % share_name]
        )
        self.storage.extend_share(share_name, new_size, share_server)
        lv_device = self.storage._get_lv_device(share_name)
        self.container.execute(
            server_id,
            ["mount", lv_device, "/shares/%s" % share_name]
        )

    def ensure_share(self, context, share, share_server=None):
        pass

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        server_id = self._get_container_name(share_server["id"])
        share_name = self._get_share_name(share)
        LOG.debug("Updating access to share %(share)s at "
                  "share server %(share_server)s.",
                  {"share_server": share_server["id"],
                   "share": share_name})
        self._get_helper(share).update_access(server_id, share_name,
                                              access_rules, add_rules,
                                              delete_rules)

    def get_network_allocations_number(self):
        return 1

    def _get_container_name(self, server_id):
        return "manila_%s" % server_id.replace("-", "_")

    def do_setup(self, *args, **kwargs):
        pass

    def check_for_setup_error(self, *args, **kwargs):
        host_id = self.configuration.safe_get("neutron_host_id")
        neutron_class = importutils.import_class(
            'manila.network.neutron.neutron_network_plugin.'
            'NeutronNetworkPlugin'
        )
        actual_class = importutils.import_class(
            self.configuration.safe_get("network_api_class"))
        if host_id is None and issubclass(actual_class, neutron_class):
            msg = _("%s requires neutron_host_id to be "
                    "specified.") % neutron_class
            raise exception.ManilaException(msg)
        elif host_id is None:
            LOG.warning("neutron_host_id is not specified. This driver "
                        "might not work as expected without it.")

    def _connect_to_network(self, server_id, network_info, host_veth,
                            host_bridge, iface):
        LOG.debug("Attempting to connect container to neutron network.")
        network_allocation = network_info["network_allocations"][0]
        port_address = network_allocation.ip_address
        port_mac = network_allocation.mac_address
        port_id = network_allocation.id
        self.container.execute(
            server_id,
            ["ifconfig", iface, port_address, "up"]
        )
        self.container.execute(
            server_id,
            ["ip", "link", "set", "dev", iface, "address", port_mac]
        )
        msg_helper = {
            'id': server_id,
            'veth': host_veth,
            'lb': host_bridge,
            'ovsb': self.configuration.container_ovs_bridge_name,
            'ip': port_address,
            'network': network_info['neutron_net_id'],
            'subnet': network_info['neutron_subnet_id'],
        }
        LOG.debug("Container %(id)s veth is %(veth)s.", msg_helper)
        LOG.debug("Removing %(veth)s from %(lb)s.", msg_helper)
        self._execute("ip", "link", "set", "dev", host_veth, "nomaster",
                      run_as_root=True)

        LOG.debug("Plugging %(veth)s into %(ovsb)s.", msg_helper)
        set_if = ['--', 'set', 'interface', host_veth]
        e_mac = set_if + ['external-ids:attached-mac="%s"' % port_mac]
        e_id = set_if + ['external-ids:iface-id="%s"' % port_id]
        e_status = set_if + ['external-ids:iface-status=active']
        e_mcid = set_if + ['external-ids:manila-container=%s' % server_id]
        self._execute("ovs-vsctl", "--", "add-port",
                      self.configuration.container_ovs_bridge_name, host_veth,
                      *(e_mac + e_id + e_status + e_mcid), run_as_root=True)
        LOG.debug("Now container %(id)s should be accessible from network "
                  "%(network)s and subnet %(subnet)s by address %(ip)s.",
                  msg_helper)

    @utils.synchronized("container_driver_teardown_lock", external=True)
    def _teardown_server(self, *args, **kwargs):
        server_id = self._get_container_name(kwargs["server_details"]["id"])
        veths = self.container.get_container_veths(server_id)
        networks = self.container.get_container_networks(server_id)

        for veth, network in zip(veths, networks):
            LOG.debug("Deleting veth %s.", veth)
            try:
                self._execute("ovs-vsctl", "--", "del-port",
                              self.configuration.container_ovs_bridge_name,
                              veth, run_as_root=True)
            except exception.ProcessExecutionError as e:
                LOG.warning("Failed to delete port %s: port vanished.", veth)
                LOG.error(e)
            self.container.disconnect_network(network, server_id)

            if network != "bridge":
                self.container.remove_network(network)

        self.container.stop_container(server_id)

    def _setup_server_network(self, server_id, network_info):
        existing_interfaces = self.container.fetch_container_interfaces(
            server_id)
        new_interfaces = []

        # If the share server network allocations are being updated, create
        # interfaces starting with ethX + 1.
        if existing_interfaces:
            ifnum_offset = len(existing_interfaces)
            for ifnum, subnet in enumerate(network_info):
                # TODO(ecsantos): Newer Ubuntu images (systemd >= 197) use
                # predictable network interface names (e.g., enp3s0) instead of
                # the classical kernel naming scheme (e.g., eth0). The
                # Container driver currently uses an Ubuntu Xenial Docker
                # image, so if it's updated in the future, these "eth" strings
                # should also be updated.
                new_interfaces.append("eth" + str(ifnum + ifnum_offset))
        # Otherwise (the share server was just created), create interfaces
        # starting with eth0.
        else:
            for ifnum, subnet in enumerate(network_info):
                new_interfaces.append("eth" + str(ifnum))

        for new_interface, subnet in zip(new_interfaces, network_info):
            network_name = "manila-docker-network-" + uuidutils.generate_uuid()
            self.container.create_network(network_name)
            self.container.connect_network(network_name, server_id)

            bridge = self.container.get_network_bridge(network_name)
            veth = self.container.get_veth_from_bridge(bridge)
            self._connect_to_network(server_id, subnet, veth, bridge,
                                     new_interface)

    @utils.synchronized("veth-lock", external=True)
    def _setup_server(self, network_info, metadata=None):
        msg = "Creating share server '%s'."
        common_net_info = network_info[0]
        server_id = self._get_container_name(common_net_info["server_id"])
        LOG.debug(msg, server_id)

        try:
            self.container.create_container(server_id)
            self.container.start_container(server_id)
        except Exception as e:
            raise exception.ManilaException(_("Cannot create container: %s") %
                                            e)

        self._setup_server_network(server_id, network_info)
        security_services = common_net_info.get('security_services')

        if security_services:
            self.setup_security_services(server_id, security_services)

        LOG.info("Container %s was created.", server_id)
        return {"id": common_net_info["server_id"]}

    def _delete_export_and_umount_storage(
            self, share, server_id, share_name, ignore_errors=False):

        self._umount_storage(
            share, server_id, share_name, ignore_errors=ignore_errors)

        # (aovchinnikov): bug 1621784 manifests itself here as well as in
        # storage helper. There is a chance that we won't be able to remove
        # this directory, despite the fact that it is not shared anymore and
        # already contains nothing. In such case the driver should not fail
        # share deletion, but issue a warning.
        self.container.execute(
            server_id,
            ["rm", "-fR", "/shares/%s" % share_name],
            ignore_errors=True
        )

    def _umount_storage(
            self, share, server_id, share_name, ignore_errors=False):

        self._get_helper(share).delete_share(server_id, share_name,
                                             ignore_errors=ignore_errors)
        self.container.execute(
            server_id,
            ["umount", "/shares/%s" % share_name],
            ignore_errors=ignore_errors
        )

    def _create_export_and_mount_storage(self, share, server_id, share_name):
        self.container.execute(
            server_id,
            ["mkdir", "-m", "750", "/shares/%s" % share_name]
        )
        return self._mount_storage(share, server_id, share_name)

    def _mount_storage(self, share, server_id, share_name):
        lv_device = self.storage._get_lv_device(share_name)
        self.container.execute(
            server_id,
            ["mount", lv_device, "/shares/%s" % share_name]
        )
        location = self._get_helper(share).create_share(server_id)
        return location

    def manage_existing_with_server(
            self, share, driver_options, share_server=None):
        if not share_server and self.driver_handles_share_servers:
            raise exception.ShareBackendException(
                "A share server object is needed to manage a share in this "
                "driver mode of operation.")
        server_id = self._get_container_name(share_server["id"])
        share_name = self._get_share_name(share)
        size = int(math.ceil(float(self.storage.get_size(share_name))))

        self._delete_export_and_umount_storage(share, server_id, share_name)

        new_share_name = share.share_id
        self.storage.rename_storage(share_name, new_share_name)

        location = self._create_export_and_mount_storage(
            share, server_id, new_share_name)

        result = {'size': size, 'export_locations': location}
        LOG.info("Successfully managed share %(share)s, returning %(data)s",
                 {'share': share.id, 'data': result})
        return result

    def unmanage_with_server(self, share, share_server=None):
        pass

    def get_share_server_network_info(
            self, context, share_server, identifier, driver_options):
        name = self._get_correct_container_old_name(identifier)
        return self.container.fetch_container_addresses(name, "inet")

    def manage_server(self, context, share_server, identifier, driver_options):
        new_name = self._get_container_name(share_server['id'])
        old_name = self._get_correct_container_old_name(identifier)
        self.container.rename_container(old_name, new_name)
        return new_name, {'id': share_server['id']}

    def unmanage_server(self, server_details, security_services=None):
        pass

    def _get_correct_container_old_name(self, name):
        # Check if the container with the given name exists, else return
        # the name based on the driver template
        if not self.container.container_exists(name):
            return self._get_container_name(name)
        return name

    def migration_check_compatibility(self, context, source_share,
                                      destination_share, share_server=None,
                                      destination_share_server=None):
        return self.storage.migration_check_compatibility(
            context, source_share, destination_share,
            share_server=share_server,
            destination_share_server=destination_share_server)

    def migration_start(self, context, source_share, destination_share,
                        source_snapshots, snapshot_mappings,
                        share_server=None, destination_share_server=None):
        self.storage.migration_start(
            context, source_share, destination_share,
            source_snapshots, snapshot_mappings,
            share_server=share_server,
            destination_share_server=destination_share_server)

    def migration_continue(self, context, source_share, destination_share,
                           source_snapshots, snapshot_mappings,
                           share_server=None, destination_share_server=None):
        return self.storage.migration_continue(
            context, source_share, destination_share,
            source_snapshots, snapshot_mappings, share_server=share_server,
            destination_share_server=destination_share_server)

    def migration_get_progress(self, context, source_share,
                               destination_share, source_snapshots,
                               snapshot_mappings, share_server=None,
                               destination_share_server=None):
        return self.storage.migration_get_progress(
            context, source_share, destination_share,
            source_snapshots, snapshot_mappings, share_server=share_server,
            destination_share_server=destination_share_server)

    def migration_cancel(self, context, source_share, destination_share,
                         source_snapshots, snapshot_mappings,
                         share_server=None, destination_share_server=None):
        self.storage.migration_cancel(
            context, source_share, destination_share,
            source_snapshots, snapshot_mappings, share_server=share_server,
            destination_share_server=destination_share_server)

    def migration_complete(self, context, source_share, destination_share,
                           source_snapshots, snapshot_mappings,
                           share_server=None, destination_share_server=None):
        # Removes the source share reference from the source container
        source_server_id = self._get_container_name(share_server["id"])
        self._umount_storage(
            source_share, source_server_id, source_share.share_id)

        # storage removes source share
        self.storage.migration_complete(
            context, source_share, destination_share,
            source_snapshots, snapshot_mappings, share_server=share_server,
            destination_share_server=destination_share_server)

        # Enables the access on the destination container
        destination_server_id = self._get_container_name(
            destination_share_server["id"])
        new_export_locations = self._mount_storage(
            destination_share, destination_server_id,
            destination_share.share_id)

        msg = ("Volume move operation for share %(shr)s was completed "
               "successfully. Share has been moved from %(src)s to "
               "%(dest)s.")
        msg_args = {
            'shr': source_share['id'],
            'src': source_share['host'],
            'dest': destination_share['host'],
        }
        LOG.info(msg, msg_args)

        return {
            'export_locations': new_export_locations,
        }

    def share_server_migration_check_compatibility(
            self, context, share_server, dest_host, old_share_network,
            new_share_network, shares_request_spec):
        """Is called to check migration compatibility for a share server."""
        return self.storage.share_server_migration_check_compatibility(
            context, share_server, dest_host, old_share_network,
            new_share_network, shares_request_spec)

    def share_server_migration_start(self, context, src_share_server,
                                     dest_share_server, shares, snapshots):
        """Is called to perform 1st phase of migration of a share server."""
        LOG.debug(
            "Migration of share server with ID '%s' has been started.",
            src_share_server["id"])
        self.storage.share_server_migration_start(
            context, src_share_server, dest_share_server, shares, snapshots)

    def share_server_migration_continue(self, context, src_share_server,
                                        dest_share_server, shares, snapshots):

        return self.storage.share_server_migration_continue(
            context, src_share_server, dest_share_server, shares, snapshots)

    def share_server_migration_cancel(self, context, src_share_server,
                                      dest_share_server, shares, snapshots):
        """Is called to cancel a share server migration."""
        self.storage.share_server_migration_cancel(
            context, src_share_server, dest_share_server, shares, snapshots)
        LOG.debug(
            "Migration of share server with ID '%s' has been canceled.",
            src_share_server["id"])
        return

    def share_server_migration_get_progress(self, context, src_share_server,
                                            dest_share_server, shares,
                                            snapshots):
        """Is called to get share server migration progress."""
        return self.storage.share_server_migration_get_progress(
            context, src_share_server, dest_share_server, shares, snapshots)

    def share_server_migration_complete(self, context, source_share_server,
                                        dest_share_server, shares, snapshots,
                                        new_network_allocations):
        # Removes the source shares reference from the source container
        source_server_id = self._get_container_name(source_share_server["id"])
        for source_share in shares:
            self._umount_storage(
                source_share, source_server_id, source_share.share_id)

        # storage removes source share
        self.storage.share_server_migration_complete(
            context, source_share_server, dest_share_server, shares, snapshots,
            new_network_allocations)

        destination_server_id = self._get_container_name(
            dest_share_server["id"])
        shares_updates = {}
        for destination_share in shares:
            share_id = destination_share.share_id
            new_export_locations = self._mount_storage(
                destination_share, destination_server_id, share_id)

            shares_updates[destination_share['id']] = {
                'export_locations': new_export_locations,
                'pool_name': self.storage.get_share_pool_name(share_id),
            }

        msg = ("Volumes move operation from server %(server)s were completed "
               "successfully. Share server has been moved from %(src)s to "
               "%(dest)s.")
        msg_args = {
            'serv': source_share_server['id'],
            'src': source_share_server['host'],
            'dest': dest_share_server['host'],
        }
        LOG.info(msg, msg_args)

        return {
            'share_updates': shares_updates,
        }

    def setup_security_services(self, share_server_id, security_services):
        """Is called to setup a security service in the share server."""

        for security_service in security_services:
            if security_service['type'].lower() != 'ldap':
                raise exception.ShareBackendException(_(
                    "The container driver does not support security services "
                    "other than LDAP."))

            self.security_service_helper.setup_security_service(
                share_server_id, security_service)

    def _get_different_security_service_keys(
            self, current_security_service, new_security_service):
        valid_keys = ['dns_ip', 'server', 'domain', 'user', 'password', 'ou']
        different_keys = []
        for key, value in current_security_service.items():
            if (current_security_service[key] != new_security_service[key]
                    and key in valid_keys):
                different_keys.append(key)
        return different_keys

    def _check_if_all_fields_are_updatable(self, current_security_service,
                                           new_security_service):
        # NOTE(carloss): We only support updating user and password at
        # the moment
        updatable_fields = ['user', 'password']
        different_keys = self._get_different_security_service_keys(
            current_security_service, new_security_service)
        for key in different_keys:
            if key not in updatable_fields:
                return False
        return True

    def update_share_server_security_service(self, context, share_server,
                                             network_info,
                                             share_instances,
                                             share_instance_rules,
                                             new_security_service,
                                             current_security_service=None):
        """Is called to update or add a sec service to a share server."""

        if not self.check_update_share_server_security_service(
                context, share_server, network_info, share_instances,
                share_instance_rules, new_security_service,
                current_security_service=current_security_service):
            raise exception.ManilaException(_(
                "The requested security service update is not supported by "
                "the container driver."))

        server_id = self._get_container_name(share_server['id'])

        if not current_security_service:
            self.setup_security_services(server_id, [new_security_service])
        else:
            self.security_service_helper.update_security_service(
                server_id, current_security_service, new_security_service)

        msg = (
            "The security service was successfully added to the share "
            "server %(server_id)s.")
        msg_args = {
            'server_id': share_server['id'],
        }
        LOG.info(msg, msg_args)

    def check_update_share_server_security_service(
            self, context, share_server, network_info, share_instances,
            share_instance_rules, new_security_service,
            current_security_service=None):
        current_type = (
            current_security_service['type'].lower()
            if current_security_service else '')
        new_type = new_security_service['type'].lower()

        if new_type != 'ldap' or (current_type and current_type != 'ldap'):
            LOG.error('Currently only LDAP security services are supported '
                      'by the container driver.')
            return False

        if not current_type:
            return True

        all_fields_are_updatable = self._check_if_all_fields_are_updatable(
            current_security_service, new_security_service)
        if not all_fields_are_updatable:
            LOG.info(
                "The Container driver does not support updating "
                "security service parameters other than 'user' and "
                "'password'.")
            return False
        return True

    def _form_share_server_update_return(self, share_server,
                                         current_network_allocations,
                                         new_network_allocations,
                                         share_instances):
        server_id = self._get_container_name(share_server["id"])
        addresses = self.container.fetch_container_addresses(server_id, "inet")
        share_updates = {}
        subnet_allocations = {}

        for share_instance in share_instances:
            export_locations = []
            for address in addresses:
                # TODO(ecsantos): The Container driver currently only
                # supports CIFS. If NFS support is implemented in the
                # future, the path should be adjusted accordingly.
                export_location = {
                    "is_admin_only": False,
                    "path": "//%(ip_address)s/%(share_id)s" %
                    {
                        "ip_address": address,
                        "share_id": share_instance["share_id"]
                    },
                    "preferred": False
                }
                export_locations.append(export_location)
            share_updates[share_instance["id"]] = export_locations

        for subnet in current_network_allocations["subnets"]:
            for network_allocation in subnet["network_allocations"]:
                subnet_allocations[network_allocation["id"]] = (
                    network_allocation["ip_address"])

        for network_allocation in (
                new_network_allocations["network_allocations"]):
            subnet_allocations[network_allocation["id"]] = (
                network_allocation["ip_address"])

        server_details = {
            "subnet_allocations": jsonutils.dumps(subnet_allocations)
        }
        return {
            "share_updates": share_updates,
            "server_details": server_details
        }

    def check_update_share_server_network_allocations(
            self, context, share_server, current_network_allocations,
            new_share_network_subnet, security_services, share_instances,
            share_instances_rules):
        LOG.debug("Share server %(server)s can be updated with allocations "
                  "from new subnet.", {"server": share_server["id"]})
        return True

    def update_share_server_network_allocations(
            self, context, share_server, current_network_allocations,
            new_network_allocations, security_services, share_instances,
            snapshots):
        server_id = self._get_container_name(share_server["id"])
        self._setup_server_network(server_id, [new_network_allocations])
        return self._form_share_server_update_return(
            share_server, current_network_allocations, new_network_allocations,
            share_instances)
