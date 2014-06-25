# Copyright (c) 2014 NetApp Inc.
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
"""NAS share manager managers creating shares and access rights.

**Related Flags**

:share_driver: Used by :class:`ShareManager`. Defaults to
                       :class:`manila.share.drivers.lvm.LVMShareDriver`.
"""

from manila.common import constants
from manila import context
from manila import exception
from manila import manager
from manila import network
from manila.openstack.common import excutils
from manila.openstack.common import importutils
from manila.openstack.common import lockutils
from manila.openstack.common import log as logging
from manila.openstack.common import timeutils
from manila import quota
from manila.share.configuration import Configuration

from oslo.config import cfg

LOG = logging.getLogger(__name__)

share_manager_opts = [
    cfg.StrOpt('share_driver',
               default='manila.share.drivers.lvm.LVMShareDriver',
               help='Driver to use for share creation'),
    cfg.BoolOpt('delete_share_server_with_last_share',
                default=False,
                help='With this option is set to True share server will'
                     'be deleted on deletion of last share'),
]

CONF = cfg.CONF
CONF.register_opts(share_manager_opts)

QUOTAS = quota.QUOTAS


class ShareManager(manager.SchedulerDependentManager):
    """Manages NAS storages."""

    RPC_API_VERSION = '1.1'

    def __init__(self, share_driver=None, service_name=None, *args, **kwargs):
        """Load the driver from args, or from flags."""
        self.configuration = Configuration(share_manager_opts,
                                           config_group=service_name)
        super(ShareManager, self).__init__(service_name='share',
                                           *args, **kwargs)

        if not share_driver:
            share_driver = self.configuration.share_driver
        self.driver = importutils.import_object(
            share_driver, self.db, configuration=self.configuration)
        self.network_api = network.API()

    def init_host(self):
        """Initialization for a standalone service."""

        ctxt = context.get_admin_context()
        self.driver.do_setup(ctxt)
        self.driver.check_for_setup_error()

        shares = self.db.share_get_all_by_host(ctxt, self.host)
        LOG.debug("Re-exporting %s shares", len(shares))
        for share in shares:
            if share['status'] in ['available', 'in-use']:
                share_server = self._get_share_server(ctxt, share)
                self.driver.ensure_share(ctxt, share,
                                         share_server=share_server)
                rules = self.db.share_access_get_all_for_share(ctxt,
                                                               share['id'])
                for access_ref in rules:
                    if access_ref['state'] == access_ref.STATE_ACTIVE:
                        try:
                            self.driver.allow_access(ctxt, share,
                                                     access_ref)
                        except exception.ShareAccessExists:
                            pass
            else:
                LOG.info(_("share %s: skipping export"), share['name'])

        self.publish_service_capabilities(ctxt)

    def _share_server_get_or_create(self, context, share_network_id):

        @lockutils.synchronized(share_network_id)
        def _get_or_create_server():
            try:
                share_server = \
                    self.db.share_server_get_by_host_and_share_net_valid(
                        context, self.host, share_network_id)
            except exception.ShareServerNotFound:
                share_network = self.db.share_network_get(
                    context, share_network_id)
                share_server = self._setup_server(context, share_network)
                LOG.info(_("Share server created successfully."))
            return share_server

        return _get_or_create_server()

    def _get_share_server(self, context, share):
        if share['share_server_id']:
            return self.db.share_server_get(
                context, share['share_server_id'])
        else:
            return None

    def create_share(self, context, share_id, request_spec=None,
                     filter_properties=None, snapshot_id=None):
        """Creates a share."""
        context = context.elevated()
        if filter_properties is None:
            filter_properties = {}

        share_ref = self.db.share_get(context, share_id)
        if snapshot_id is not None:
            snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
            parent_share_server_id = snapshot_ref['share']['share_server_id']
        else:
            snapshot_ref = None
            parent_share_server_id = None

        share_network_id = share_ref.get('share_network_id', None)

        if parent_share_server_id:
            try:
                share_server = self.db.share_server_get(context,
                                                        parent_share_server_id)
            except exception.ShareServerNotFound:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("Share server %s does not exist.")
                              % parent_share_server_id)
                    self.db.share_update(context, share_id,
                                         {'status': 'error'})
        elif share_network_id:
            try:
                share_server = self._share_server_get_or_create(
                    context, share_network_id)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("Failed to get share server"
                                " for share creation."))
                    self.db.share_update(context, share_id,
                                         {'status': 'error'})
        else:
            share_server = None

        if share_server:
            LOG.debug("Using share server %s" % share_server['id'])
            share_ref = self.db.share_update(
                context, share_id, {'share_server_id': share_server['id']})

        try:
            if snapshot_ref:
                export_location = self.driver.create_share_from_snapshot(
                    context, share_ref, snapshot_ref,
                    share_server=share_server)
            else:
                export_location = self.driver.create_share(
                    context, share_ref, share_server=share_server)
            self.db.share_update(context, share_id,
                                 {'export_location': export_location})
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("Share %s failed on creation.") % share_id)
                self.db.share_update(context, share_id, {'status': 'error'})
        else:
            LOG.info(_("Share created successfully."))
            self.db.share_update(context, share_id,
                                 {'status': 'available',
                                  'launched_at': timeutils.utcnow()})

    def delete_share(self, context, share_id):
        """Delete a share."""
        context = context.elevated()
        share_ref = self.db.share_get(context, share_id)
        share_server = self._get_share_server(context, share_ref)

        if context.project_id != share_ref['project_id']:
            project_id = share_ref['project_id']
        else:
            project_id = context.project_id
        rules = self.db.share_access_get_all_for_share(context, share_id)
        try:
            for access_ref in rules:
                self._deny_access(context, access_ref, share_ref, share_server)
            self.driver.delete_share(context, share_ref,
                                     share_server=share_server)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_update(context, share_id,
                                     {'status': 'error_deleting'})
        try:
            reservations = QUOTAS.reserve(context,
                                          project_id=project_id,
                                          shares=-1,
                                          gigabytes=-share_ref['size'])
        except Exception:
            reservations = None
            LOG.exception(_("Failed to update usages deleting share"))

        self.db.share_delete(context, share_id)
        LOG.info(_("Share %s: deleted successfully."), share_ref['name'])

        if reservations:
            QUOTAS.commit(context, reservations, project_id=project_id)

        if CONF.delete_share_server_with_last_share:
            share_server = self._get_share_server(context, share_ref)
            if share_server and not share_server.shares:
                self._teardown_server(context, share_server)

    def create_snapshot(self, context, share_id, snapshot_id):
        """Create snapshot for share."""
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
        share_server = self._get_share_server(context,
                                              snapshot_ref['share'])
        try:
            model_update = self.driver.create_snapshot(
                context, snapshot_ref, share_server=share_server)
            if model_update:
                self.db.share_snapshot_update(context, snapshot_ref['id'],
                                              model_update)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_snapshot_update(context,
                                              snapshot_ref['id'],
                                              {'status': 'error'})

        self.db.share_snapshot_update(context,
                                      snapshot_ref['id'],
                                      {'status': 'available',
                                       'progress': '100%'})
        return snapshot_id

    def delete_snapshot(self, context, snapshot_id):
        """Delete share snapshot."""
        context = context.elevated()
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)

        share_server = self._get_share_server(context,
                                              snapshot_ref['share'])

        if context.project_id != snapshot_ref['project_id']:
            project_id = snapshot_ref['project_id']
        else:
            project_id = context.project_id

        try:
            self.driver.delete_snapshot(context, snapshot_ref,
                                        share_server=share_server)
        except exception.ShareSnapshotIsBusy:
            self.db.share_snapshot_update(context, snapshot_ref['id'],
                                          {'status': 'available'})
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_snapshot_update(context, snapshot_ref['id'],
                                              {'status': 'error_deleting'})
        else:
            self.db.share_snapshot_destroy(context, snapshot_id)
            try:
                reservations = QUOTAS.reserve(context,
                                              project_id=project_id,
                                              snapshots=-1,
                                              gigabytes=-snapshot_ref['size'])
            except Exception:
                reservations = None
                LOG.exception(_("Failed to update usages deleting snapshot"))

            if reservations:
                QUOTAS.commit(context, reservations, project_id=project_id)

    def allow_access(self, context, access_id):
        """Allow access to some share."""
        try:
            access_ref = self.db.share_access_get(context, access_id)
            share_ref = self.db.share_get(context, access_ref['share_id'])
            share_server = self._get_share_server(context,
                                                  share_ref)
            if access_ref['state'] == access_ref.STATE_NEW:
                self.driver.allow_access(context, share_ref, access_ref,
                                         share_server=share_server)
                self.db.share_access_update(
                    context, access_id, {'state': access_ref.STATE_ACTIVE})
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_access_update(
                    context, access_id, {'state': access_ref.STATE_ERROR})

    def deny_access(self, context, access_id):
        """Deny access to some share."""
        access_ref = self.db.share_access_get(context, access_id)
        share_ref = self.db.share_get(context, access_ref['share_id'])
        share_server = self._get_share_server(context,
                                              share_ref)
        self._deny_access(context, access_ref, share_ref, share_server)

    def _deny_access(self, context, access_ref, share_ref, share_server):
        access_id = access_ref['id']
        try:
            self.driver.deny_access(context, share_ref, access_ref,
                                    share_server=share_server)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_access_update(
                    context, access_id, {'state': access_ref.STATE_ERROR})
        self.db.share_access_delete(context, access_id)

    @manager.periodic_task
    def _report_driver_status(self, context):
        LOG.info(_('Updating share status'))
        share_stats = self.driver.get_share_stats(refresh=True)
        if share_stats:
            self.update_service_capabilities(share_stats)

    def publish_service_capabilities(self, context):
        """Collect driver status and then publish it."""
        self._report_driver_status(context)
        self._publish_service_capabilities(context)

    def _form_server_setup_info(self, context, share_server, share_network):
        # Network info is used by driver for setting up share server
        # and getting server info on share creation.
        network_allocations = self.db.network_allocations_get_for_share_server(
            context, share_server['id'])
        network_info = {
            'server_id': share_server['id'],
            'segmentation_id': share_network['segmentation_id'],
            'cidr': share_network['cidr'],
            'neutron_net_id': share_network['neutron_net_id'],
            'neutron_subnet_id': share_network['neutron_subnet_id'],
            'security_services': share_network['security_services'],
            'network_allocations': network_allocations,
            'backend_details': share_server.get('backend_details'),
        }
        return network_info

    def _setup_server(self, context, share_network, metadata=None):
        share_server_val = {
            'host': self.host,
            'share_network_id': share_network['id'],
            'status': constants.STATUS_CREATING
        }
        share_server = self.db.share_server_create(context,
                                                   share_server_val)

        try:
            allocation_number = self.driver.get_network_allocations_number()
            if allocation_number:
                self.network_api.allocate_network(
                    context, share_server, share_network,
                    count=allocation_number)

            share_network = self.db.share_network_get(context,
                                                      share_network['id'])
            network_info = self._form_server_setup_info(context, share_server,
                                                        share_network)
            server_info = self.driver.setup_server(network_info,
                                                   metadata=metadata)
            if server_info and isinstance(server_info, dict):
                self.db.share_server_backend_details_set(context,
                                                         share_server['id'],
                                                         server_info)
            return self.db.share_server_update(
                context, share_server['id'],
                {'status': constants.STATUS_ACTIVE})
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_server_update(context, share_server['id'],
                    {'status': constants.STATUS_ERROR})
                self.network_api.deallocate_network(context, share_network)

    def _teardown_server(self, context, share_server):

        @lockutils.synchronized(share_server['share_network_id'])
        def _teardown_server():
            self.db.share_server_update(context, share_server['id'],
                                        {'status': constants.STATUS_DELETING})
            sec_services = self.db.share_network_get(
                context,
                share_server['share_network_id'])['security_services']
            try:
                LOG.debug("Deleting share server")
                self.driver.teardown_server(share_server['backend_details'],
                                            security_services=sec_services)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("Share server %s failed on deletion.")
                              % share_server['id'])
                    self.db.share_server_update(context, share_server['id'],
                        {'status': constants.STATUS_ERROR})
            else:
                self.db.share_server_delete(context, share_server['id'])

        _teardown_server()
        LOG.info(_("Share server deleted successfully."))
        self.network_api.deallocate_network(context, share_server)
