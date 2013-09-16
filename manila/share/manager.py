# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 NetApp
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

from manila import context
from manila import exception
from manila import flags
from manila import manager
from manila.openstack.common import excutils
from manila.openstack.common import importutils
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
]

FLAGS = flags.FLAGS
FLAGS.register_opts(share_manager_opts)

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
                        share_driver,
                        self.db,
                        configuration=self.configuration)

    def init_host(self):
        """Initialization for a standalone service."""

        ctxt = context.get_admin_context()
        self.driver.do_setup(ctxt)
        self.driver.check_for_setup_error()

        shares = self.db.share_get_all_by_host(ctxt, self.host)
        LOG.debug(_("Re-exporting %s shares"), len(shares))
        for share in shares:
            if share['status'] in ['available', 'in-use']:
                self.driver.ensure_share(ctxt, share)
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

    def create_share(self, context, share_id, request_spec=None,
                     filter_properties=None, snapshot_id=None):
        """Creates a share."""
        context = context.elevated()
        if filter_properties is None:
            filter_properties = {}

        share_ref = self.db.share_get(context, share_id)
        if snapshot_id is not None:
            snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
        else:
            snapshot_ref = None

        try:
            if snapshot_ref:
                self.driver.allocate_container_from_snapshot(context,
                                                             share_ref,
                                                             snapshot_ref)
            else:
                self.driver.allocate_container(context, share_ref)
            export_location = self.driver.create_share(context, share_ref)
            self.db.share_update(context, share_id,
                                 {'export_location': export_location})
            self.driver.create_export(context, share_ref)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_update(context, share_id, {'status': 'error'})
        else:
            self.db.share_update(context, share_id,
                                 {'status': 'available',
                                  'launched_at': timeutils.utcnow()})

    def delete_share(self, context, share_id):
        """Delete a share."""
        context = context.elevated()
        share_ref = self.db.share_get(context, share_id)

        if context.project_id != share_ref['project_id']:
            project_id = share_ref['project_id']
        else:
            project_id = context.project_id
        rules = self.db.share_access_get_all_for_share(context, share_id)
        try:
            for access_ref in rules:
                self._deny_access(context, access_ref, share_ref)
            self.driver.remove_export(context, share_ref)
            self.driver.delete_share(context, share_ref)
            self.driver.deallocate_container(context, share_ref)
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
        LOG.info(_("share %s: deleted successfully"), share_ref['name'])

        if reservations:
            QUOTAS.commit(context, reservations, project_id=project_id)

    def create_snapshot(self, context, share_id, snapshot_id):
        """Create snapshot for share."""
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)

        try:
            snap_name = snapshot_ref['name']
            model_update = self.driver.create_snapshot(context, snapshot_ref)
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

        if context.project_id != snapshot_ref['project_id']:
            project_id = snapshot_ref['project_id']
        else:
            project_id = context.project_id

        try:
            self.driver.delete_snapshot(context, snapshot_ref)
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
                                          shares=-1,
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
            if access_ref['state'] == access_ref.STATE_NEW:
                self.driver.allow_access(context, share_ref, access_ref)
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
        self._deny_access(context, access_ref, share_ref)

    def _deny_access(self, context, access_ref, share_ref):
        access_id = access_ref['id']
        try:
            self.driver.deny_access(context, share_ref, access_ref)
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
