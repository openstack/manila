# Copyright (c) 2015 Hitachi Data Systems.
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
"""Helper class for Share Migration."""

import time

from oslo_config import cfg
from oslo_log import log

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import api as share_api
import manila.utils as utils


LOG = log.getLogger(__name__)

migration_opts = [
    cfg.IntOpt(
        'migration_wait_access_rules_timeout',
        default=180,
        help="Time to wait for access rules to be allowed/denied on backends "
             "when migrating shares using generic approach (seconds)."),
    cfg.IntOpt(
        'migration_create_delete_share_timeout',
        default=300,
        help='Timeout for creating and deleting share instances '
             'when performing share migration (seconds).'),
]

CONF = cfg.CONF
CONF.register_opts(migration_opts)


class ShareMigrationHelper(object):

    def __init__(self, context, db, share, access_helper):

        self.db = db
        self.share = share
        self.context = context
        self.access_helper = access_helper
        self.api = share_api.API()
        self.access_helper = access_helper

        self.migration_create_delete_share_timeout = (
            CONF.migration_create_delete_share_timeout)
        self.migration_wait_access_rules_timeout = (
            CONF.migration_wait_access_rules_timeout)

    def delete_instance_and_wait(self, share_instance):

        self.api.delete_instance(self.context, share_instance, True)

        # Wait for deletion.
        starttime = time.time()
        deadline = starttime + self.migration_create_delete_share_timeout
        tries = 0
        instance = "Something not None"
        while instance is not None:
            try:
                instance = self.db.share_instance_get(self.context,
                                                      share_instance['id'])
                tries += 1
                now = time.time()
                if now > deadline:
                    msg = _("Timeout trying to delete instance "
                            "%s") % share_instance['id']
                    raise exception.ShareMigrationFailed(reason=msg)
            except exception.NotFound:
                instance = None
            else:
                # 1.414 = square-root of 2
                time.sleep(1.414 ** tries)

    def create_instance_and_wait(self, share, dest_host, new_share_network_id,
                                 new_az_id, new_share_type_id):

        new_share_instance = self.api.create_instance(
            self.context, share, new_share_network_id, dest_host,
            new_az_id, share_type_id=new_share_type_id)

        # Wait for new_share_instance to become ready
        starttime = time.time()
        deadline = starttime + self.migration_create_delete_share_timeout
        new_share_instance = self.db.share_instance_get(
            self.context, new_share_instance['id'], with_share_data=True)
        tries = 0
        while new_share_instance['status'] != constants.STATUS_AVAILABLE:
            tries += 1
            now = time.time()
            if new_share_instance['status'] == constants.STATUS_ERROR:
                msg = _("Failed to create new share instance"
                        " (from %(share_id)s) on "
                        "destination host %(host_name)s") % {
                    'share_id': share['id'], 'host_name': dest_host}
                self.cleanup_new_instance(new_share_instance)
                raise exception.ShareMigrationFailed(reason=msg)
            elif now > deadline:
                msg = _("Timeout creating new share instance "
                        "(from %(share_id)s) on "
                        "destination host %(host_name)s") % {
                    'share_id': share['id'], 'host_name': dest_host}
                self.cleanup_new_instance(new_share_instance)
                raise exception.ShareMigrationFailed(reason=msg)
            else:
                # 1.414 = square-root of 2
                time.sleep(1.414 ** tries)
            new_share_instance = self.db.share_instance_get(
                self.context, new_share_instance['id'], with_share_data=True)

        return new_share_instance

    # NOTE(ganso): Cleanup methods do not throw exceptions, since the
    # exceptions that should be thrown are the ones that call the cleanup

    def cleanup_new_instance(self, new_instance):

        try:
            self.delete_instance_and_wait(new_instance)
        except Exception:
            LOG.warning("Failed to cleanup new instance during generic"
                        " migration for share %s.", self.share['id'])

    def cleanup_access_rules(self, share_instance, share_server):

        try:
            self.revert_access_rules(share_instance, share_server)
        except Exception:
            LOG.warning("Failed to cleanup access rules during generic"
                        " migration for share %s.", self.share['id'])

    def revert_access_rules(self, share_instance, share_server):

        # Cast all rules to 'queued_to_apply' so that they can be re-applied.
        updates = {'state': constants.ACCESS_STATE_QUEUED_TO_APPLY}
        self.access_helper.get_and_update_share_instance_access_rules(
            self.context, updates=updates,
            share_instance_id=share_instance['id'])

        self.access_helper.update_access_rules(
            self.context, share_instance['id'], share_server=share_server)

        utils.wait_for_access_update(
            self.context, self.db, share_instance,
            self.migration_wait_access_rules_timeout)

    def apply_new_access_rules(self, new_share_instance):

        rules = self.db.share_instance_access_copy(
            self.context, self.share['id'], new_share_instance['id'])

        if rules:
            self.api.allow_access_to_instance(self.context, new_share_instance)

            utils.wait_for_access_update(
                self.context, self.db, new_share_instance,
                self.migration_wait_access_rules_timeout)
        else:
            LOG.debug("No access rules to sync to destination share instance.")

    @utils.retry(exception.ShareServerNotReady, retries=8)
    def wait_for_share_server(self, share_server_id):
        share_server = self.db.share_server_get(self.context, share_server_id)
        if share_server['status'] == constants.STATUS_ERROR:
            raise exception.ShareServerNotCreated(
                share_server_id=share_server_id)
        elif share_server['status'] == constants.STATUS_ACTIVE:
            return share_server
        else:
            raise exception.ShareServerNotReady(
                share_server_id=share_server_id, time=511,
                state=constants.STATUS_AVAILABLE)
