# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2014 Mirantis, Inc.
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

import ddt

from manila import exception
from manila import test


class FakeNotifier(object):
    """Acts like the manila.openstack.common.notifier.api module."""
    ERROR = 88

    def __init__(self):
        self.provided_publisher = None
        self.provided_event = None
        self.provided_priority = None
        self.provided_payload = None

    def notify(self, context, publisher, event, priority, payload):
        self.provided_publisher = publisher
        self.provided_event = event
        self.provided_priority = priority
        self.provided_payload = payload


@ddt.ddt
class ManilaExceptionTestCase(test.TestCase):
    def test_default_error_msg(self):
        class FakeManilaException(exception.ManilaException):
            message = "default message"

        exc = FakeManilaException()
        self.assertEqual('default message', str(exc))

    def test_error_msg(self):
        self.assertEqual('test',
                         str(exception.ManilaException('test')))

    def test_default_error_msg_with_kwargs(self):
        class FakeManilaException(exception.ManilaException):
            message = "default message: %(code)s"

        exc = FakeManilaException(code=500)
        self.assertEqual('default message: 500', str(exc))

    def test_error_msg_exception_with_kwargs(self):
        # NOTE(dprince): disable format errors for this test
        self.flags(fatal_exception_format_errors=False)

        class FakeManilaException(exception.ManilaException):
            message = "default message: %(misspelled_code)s"

        exc = FakeManilaException(code=500)
        self.assertEqual('default message: %(misspelled_code)s',
                         str(exc))

    def test_default_error_code(self):
        class FakeManilaException(exception.ManilaException):
            code = 404

        exc = FakeManilaException()
        self.assertEqual(404, exc.kwargs['code'])

    def test_error_code_from_kwarg(self):
        class FakeManilaException(exception.ManilaException):
            code = 500

        exc = FakeManilaException(code=404)
        self.assertEqual(404, exc.kwargs['code'])

    def test_error_msg_is_exception_to_string(self):
        msg = 'test message'
        exc1 = Exception(msg)
        exc2 = exception.ManilaException(exc1)
        self.assertEqual(msg, exc2.msg)

    def test_exception_kwargs_to_string(self):
        msg = 'test message'
        exc1 = Exception(msg)
        exc2 = exception.ManilaException(kwarg1=exc1)
        self.assertEqual(msg, exc2.kwargs['kwarg1'])

    def test_exception_multi_kwargs_to_string(self):
        exc = exception.ManilaException(
            'fake_msg', foo=Exception('foo_msg'), bar=Exception('bar_msg'))
        self.assertEqual('fake_msg', exc.msg)
        self.assertEqual('foo_msg', exc.kwargs['foo'])
        self.assertEqual('bar_msg', exc.kwargs['bar'])
        self.assertNotIn('fake_msg', exc.kwargs)
        self.assertNotIn('foo_msg', exc.kwargs)
        self.assertNotIn('bar_msg', exc.kwargs)

    @ddt.data("test message.", "test message....", ".")
    def test_exception_not_redundant_period(self, msg):
        exc1 = Exception(msg)
        exc2 = exception.ManilaException(exc1)
        self.assertEqual(msg, exc2.msg)

    def test_exception_redundant_period(self):
        msg = "test message.."
        exc1 = Exception(msg)
        exc2 = exception.ManilaException(exc1)
        self.assertEqual("test message.", exc2.msg)

    def test_replication_exception(self):
        # Verify response code for exception.ReplicationException
        reason = "Something bad happened."
        e = exception.ReplicationException(reason=reason)
        self.assertEqual(500, e.code)
        self.assertIn(reason, e.msg)

    def test_snapshot_access_already_exists(self):
        # Verify response code for exception.ShareSnapshotAccessExists
        access_type = "fake_type"
        access = "fake_access"
        e = exception.ShareSnapshotAccessExists(access_type=access_type,
                                                access=access)
        self.assertEqual(400, e.code)
        self.assertIn(access_type, e.msg)
        self.assertIn(access, e.msg)

    def test_manage_share_server_error(self):
        # Verify response code for exception.ManageShareServerError
        reason = 'Invalid share server id.'
        share_server_id = 'fake'
        e = exception.ManageShareServerError(reason=reason,
                                             share_server_id=share_server_id)

        self.assertEqual(500, e.code)
        self.assertIn(reason, e.msg)

    def test_ip_address_generation_failure(self):
        # verify response code for exception.IpAddressGenerationFailureClient
        e = exception.IpAddressGenerationFailureClient()
        self.assertEqual(500, e.code)


class ManilaExceptionResponseCode400(test.TestCase):

    def test_invalid(self):
        # Verify response code for exception.Invalid
        e = exception.Invalid()
        self.assertEqual(400, e.code)

    def test_invalid_input(self):
        # Verify response code for exception.InvalidInput
        reason = "fake_reason"
        e = exception.InvalidInput(reason=reason)
        self.assertEqual(400, e.code)
        self.assertIn(reason, e.msg)

    def test_invalid_request(self):
        # Verify response code for exception.InvalidRequest
        e = exception.InvalidRequest()
        self.assertEqual(400, e.code)

    def test_invalid_results(self):
        # Verify response code for exception.InvalidResults
        e = exception.InvalidResults()
        self.assertEqual(400, e.code)

    def test_invalid_uuid(self):
        # Verify response code for exception.InvalidUUID
        uuid = "fake_uuid"
        e = exception.InvalidUUID(uuid=uuid)
        self.assertEqual(400, e.code)
        self.assertIn(uuid, e.msg)

    def test_invalid_content_type(self):
        # Verify response code for exception.InvalidContentType
        content_type = "fake_content_type"
        e = exception.InvalidContentType(content_type=content_type)
        self.assertEqual(400, e.code)
        self.assertIn(content_type, e.msg)

    def test_invalid_parameter_value(self):
        # Verify response code for exception.InvalidParameterValue
        err = "fake_err"
        e = exception.InvalidParameterValue(err=err)
        self.assertEqual(400, e.code)
        self.assertIn(err, e.msg)

    def test_invalid_reservation_expiration(self):
        # Verify response code for exception.InvalidReservationExpiration
        expire = "fake_expire"
        e = exception.InvalidReservationExpiration(expire=expire)
        self.assertEqual(400, e.code)
        self.assertIn(expire, e.msg)

    def test_invalid_quota_value(self):
        # Verify response code for exception.InvalidQuotaValue
        unders = '-1'
        e = exception.InvalidQuotaValue(unders=unders)
        self.assertEqual(400, e.code)

    def test_invalid_share(self):
        # Verify response code for exception.InvalidShare
        reason = "fake_reason"
        e = exception.InvalidShare(reason=reason)
        self.assertEqual(400, e.code)
        self.assertIn(reason, e.msg)

    def test_invalid_share_access(self):
        # Verify response code for exception.InvalidShareAccess
        reason = "fake_reason"
        e = exception.InvalidShareAccess(reason=reason)
        self.assertEqual(400, e.code)
        self.assertIn(reason, e.msg)

    def test_invalid_share_snapshot(self):
        # Verify response code for exception.InvalidShareSnapshot
        reason = "fake_reason"
        e = exception.InvalidShareSnapshot(reason=reason)
        self.assertEqual(400, e.code)
        self.assertIn(reason, e.msg)

    def test_invalid_share_metadata(self):
        # Verify response code for exception.InvalidMetadata
        e = exception.InvalidMetadata()
        self.assertEqual(400, e.code)

    def test_invalid_share_metadata_size(self):
        # Verify response code for exception.InvalidMetadataSize
        e = exception.InvalidMetadataSize()
        self.assertEqual(400, e.code)

    def test_invalid_volume(self):
        # Verify response code for exception.InvalidVolume
        e = exception.InvalidVolume()
        self.assertEqual(400, e.code)

    def test_invalid_share_type(self):
        # Verify response code for exception.InvalidShareType
        reason = "fake_reason"
        e = exception.InvalidShareType(reason=reason)
        self.assertEqual(400, e.code)
        self.assertIn(reason, e.msg)

    def test_manage_invalid_share_snapshot(self):
        # Verify response code for exception.ManageInvalidShareSnapshot
        reason = "fake_reason"
        e = exception.ManageInvalidShareSnapshot(reason=reason)
        self.assertEqual(400, e.code)
        self.assertIn(reason, e.msg)

    def test_unmanage_invalid_share_snapshot(self):
        # Verify response code for exception.UnmanageInvalidShareSnapshot
        reason = "fake_reason"
        e = exception.UnmanageInvalidShareSnapshot(reason=reason)
        self.assertEqual(400, e.code)
        self.assertIn(reason, e.msg)

    def test_invalid_share_snapshot_instance(self):
        # Verify response code for exception.InvalidShareSnapshotInstance
        reason = "fake_reason"
        e = exception.InvalidShareSnapshotInstance(reason=reason)
        self.assertEqual(400, e.code)
        self.assertIn(reason, e.msg)


class ManilaExceptionResponseCode403(test.TestCase):

    def test_not_authorized(self):
        # Verify response code for exception.NotAuthorized
        e = exception.NotAuthorized()
        self.assertEqual(403, e.code)

    def test_admin_required(self):
        # Verify response code for exception.AdminRequired
        e = exception.AdminRequired()
        self.assertEqual(403, e.code)

    def test_policy_not_authorized(self):
        # Verify response code for exception.PolicyNotAuthorized
        action = "fake_action"
        e = exception.PolicyNotAuthorized(action=action)
        self.assertEqual(403, e.code)
        self.assertIn(action, e.msg)


class ManilaExceptionResponseCode404(test.TestCase):

    def test_not_found(self):
        # Verify response code for exception.NotFound
        e = exception.NotFound()
        self.assertEqual(404, e.code)

    def test_share_network_not_found(self):
        # Verify response code for exception.ShareNetworkNotFound
        share_network_id = "fake_share_network_id"
        e = exception.ShareNetworkNotFound(share_network_id=share_network_id)
        self.assertEqual(404, e.code)
        self.assertIn(share_network_id, e.msg)

    def test_share_network_subnet_not_found(self):
        # Verify response code for exception.ShareNetworkSubnetNotFound
        share_network_subnet_id = "fake_share_network_subnet_id"
        e = exception.ShareNetworkSubnetNotFound(
            share_network_subnet_id=share_network_subnet_id)
        self.assertEqual(404, e.code)
        self.assertIn(share_network_subnet_id, e.msg)

    def test_share_server_not_found(self):
        # Verify response code for exception.ShareServerNotFound
        share_server_id = "fake_share_server_id"
        e = exception.ShareServerNotFound(share_server_id=share_server_id)
        self.assertEqual(404, e.code)
        self.assertIn(share_server_id, e.msg)

    def test_share_server_not_found_by_filters(self):
        # Verify response code for exception.ShareServerNotFoundByFilters
        filters_description = "host = fakeHost"
        e = exception.ShareServerNotFoundByFilters(
            filters_description=filters_description)
        self.assertEqual(404, e.code)
        self.assertIn(filters_description, e.msg)

    def test_service_not_found(self):
        # Verify response code for exception.ServiceNotFound
        service_id = "fake_service_id"
        e = exception.ServiceNotFound(service_id=service_id)
        self.assertEqual(404, e.code)
        self.assertIn(service_id, e.msg)

    def test_host_not_found(self):
        # Verify response code for exception.HostNotFound
        host = "fake_host"
        e = exception.HostNotFound(host=host)
        self.assertEqual(404, e.code)
        self.assertIn(host, e.msg)

    def test_scheduler_host_filter_not_found(self):
        # Verify response code for exception.SchedulerHostFilterNotFound
        filter_name = "fake_filter_name"
        e = exception.SchedulerHostFilterNotFound(filter_name=filter_name)
        self.assertEqual(404, e.code)
        self.assertIn(filter_name, e.msg)

    def test_scheduler_host_weigher_not_found(self):
        # Verify response code for exception.SchedulerHostWeigherNotFound
        weigher_name = "fake_weigher_name"
        e = exception.SchedulerHostWeigherNotFound(weigher_name=weigher_name)
        self.assertEqual(404, e.code)
        self.assertIn(weigher_name, e.msg)

    def test_host_binary_not_found(self):
        # Verify response code for exception.HostBinaryNotFound
        host = "fake_host"
        binary = "fake_binary"
        e = exception.HostBinaryNotFound(binary=binary, host=host)
        self.assertEqual(404, e.code)
        self.assertIn(binary, e.msg)
        self.assertIn(host, e.msg)

    def test_quota_not_found(self):
        # Verify response code for exception.QuotaNotFound
        e = exception.QuotaNotFound()
        self.assertEqual(404, e.code)

    def test_quota_resource_unknown(self):
        # Verify response code for exception.QuotaResourceUnknown
        unknown = "fake_quota_resource"
        e = exception.QuotaResourceUnknown(unknown=unknown)
        self.assertEqual(404, e.code)

    def test_project_quota_not_found(self):
        # Verify response code for exception.ProjectQuotaNotFound
        project_id = "fake_tenant_id"
        e = exception.ProjectQuotaNotFound(project_id=project_id)
        self.assertEqual(404, e.code)

    def test_quota_class_not_found(self):
        # Verify response code for exception.QuotaClassNotFound
        class_name = "FakeQuotaClass"
        e = exception.QuotaClassNotFound(class_name=class_name)
        self.assertEqual(404, e.code)

    def test_quota_usage_not_found(self):
        # Verify response code for exception.QuotaUsageNotFound
        project_id = "fake_tenant_id"
        e = exception.QuotaUsageNotFound(project_id=project_id)
        self.assertEqual(404, e.code)

    def test_reservation_not_found(self):
        # Verify response code for exception.ReservationNotFound
        uuid = "fake_uuid"
        e = exception.ReservationNotFound(uuid=uuid)
        self.assertEqual(404, e.code)

    def test_migration_not_found(self):
        # Verify response code for exception.MigrationNotFound
        migration_id = "fake_migration_id"
        e = exception.MigrationNotFound(migration_id=migration_id)
        self.assertEqual(404, e.code)
        self.assertIn(migration_id, e.msg)

    def test_migration_not_found_by_status(self):
        # Verify response code for exception.MigrationNotFoundByStatus
        status = "fake_status"
        instance_id = "fake_instance_id"
        e = exception.MigrationNotFoundByStatus(status=status,
                                                instance_id=instance_id)
        self.assertEqual(404, e.code)
        self.assertIn(status, e.msg)
        self.assertIn(instance_id, e.msg)

    def test_file_not_found(self):
        # Verify response code for exception.FileNotFound
        file_path = "fake_file_path"
        e = exception.FileNotFound(file_path=file_path)
        self.assertEqual(404, e.code)
        self.assertIn(file_path, e.msg)

    def test_config_not_found(self):
        # Verify response code for exception.ConfigNotFound
        path = "fake_path"
        e = exception.ConfigNotFound(path=path)
        self.assertEqual(404, e.code)
        self.assertIn(path, e.msg)

    def test_paste_app_not_found(self):
        # Verify response code for exception.PasteAppNotFound
        name = "fake_name"
        path = "fake_path"
        e = exception.PasteAppNotFound(name=name, path=path)
        self.assertEqual(404, e.code)
        self.assertIn(name, e.msg)
        self.assertIn(path, e.msg)

    def test_share_snapshot_not_found(self):
        # Verify response code for exception.ShareSnapshotNotFound
        snapshot_id = "fake_snapshot_id"
        e = exception.ShareSnapshotNotFound(snapshot_id=snapshot_id)
        self.assertEqual(404, e.code)
        self.assertIn(snapshot_id, e.msg)

    def test_metadata_item_not_found(self):
        # verify response code for exception.MetadataItemNotFound
        e = exception.MetadataItemNotFound()
        self.assertEqual(404, e.code)

    def test_security_service_not_found(self):
        # verify response code for exception.SecurityServiceNotFound
        security_service_id = "fake_security_service_id"
        e = exception.SecurityServiceNotFound(
            security_service_id=security_service_id)
        self.assertEqual(404, e.code)
        self.assertIn(security_service_id, e.msg)

    def test_volume_not_found(self):
        # verify response code for exception.VolumeNotFound
        volume_id = "fake_volume_id"
        e = exception.VolumeNotFound(volume_id=volume_id)
        self.assertEqual(404, e.code)
        self.assertIn(volume_id, e.msg)

    def test_volume_snapshot_not_found(self):
        # verify response code for exception.VolumeSnapshotNotFound
        snapshot_id = "fake_snapshot_id"
        e = exception.VolumeSnapshotNotFound(snapshot_id=snapshot_id)
        self.assertEqual(404, e.code)
        self.assertIn(snapshot_id, e.msg)

    def test_share_type_not_found(self):
        # verify response code for exception.ShareTypeNotFound
        share_type_id = "fake_share_type_id"
        e = exception.ShareTypeNotFound(share_type_id=share_type_id)
        self.assertEqual(404, e.code)
        self.assertIn(share_type_id, e.msg)

    def test_share_type_not_found_by_name(self):
        # verify response code for exception.ShareTypeNotFoundByName
        share_type_name = "fake_share_type_name"
        e = exception.ShareTypeNotFoundByName(
            share_type_name=share_type_name)
        self.assertEqual(404, e.code)
        self.assertIn(share_type_name, e.msg)

    def test_share_type_does_not_exist(self):
        # verify response code for exception.ShareTypeDoesNotExist
        share_type = "fake_share_type_1234"
        e = exception.ShareTypeDoesNotExist(share_type=share_type)
        self.assertEqual(404, e.code)
        self.assertIn(share_type, e.msg)

    def test_share_type_extra_specs_not_found(self):
        # verify response code for exception.ShareTypeExtraSpecsNotFound
        share_type_id = "fake_share_type_id"
        extra_specs_key = "fake_extra_specs_key"
        e = exception.ShareTypeExtraSpecsNotFound(
            share_type_id=share_type_id, extra_specs_key=extra_specs_key)
        self.assertEqual(404, e.code)
        self.assertIn(share_type_id, e.msg)
        self.assertIn(extra_specs_key, e.msg)

    def test_default_share_type_not_configured(self):
        # Verify response code for exception.DefaultShareTypeNotConfigured
        e = exception.DefaultShareTypeNotConfigured()
        self.assertEqual(404, e.code)

    def test_instance_not_found(self):
        # verify response code for exception.InstanceNotFound
        instance_id = "fake_instance_id"
        e = exception.InstanceNotFound(instance_id=instance_id)
        self.assertEqual(404, e.code)
        self.assertIn(instance_id, e.msg)

    def test_share_replica_not_found_exception(self):
        # Verify response code for exception.ShareReplicaNotFound
        replica_id = "FAKE_REPLICA_ID"
        e = exception.ShareReplicaNotFound(replica_id=replica_id)
        self.assertEqual(404, e.code)
        self.assertIn(replica_id, e.msg)

    def test_storage_resource_not_found(self):
        # verify response code for exception.StorageResourceNotFound
        name = "fake_name"
        e = exception.StorageResourceNotFound(name=name)
        self.assertEqual(404, e.code)
        self.assertIn(name, e.msg)

    def test_snapshot_resource_not_found(self):
        # verify response code for exception.SnapshotResourceNotFound
        name = "fake_name"
        e = exception.SnapshotResourceNotFound(name=name)
        self.assertEqual(404, e.code)
        self.assertIn(name, e.msg)

    def test_snapshot_instance_not_found(self):
        # verify response code for exception.ShareSnapshotInstanceNotFound
        instance_id = 'fake_instance_id'
        e = exception.ShareSnapshotInstanceNotFound(instance_id=instance_id)
        self.assertEqual(404, e.code)
        self.assertIn(instance_id, e.msg)

    def test_export_location_not_found(self):
        # verify response code for exception.ExportLocationNotFound
        uuid = "fake-export-location-uuid"
        e = exception.ExportLocationNotFound(uuid=uuid)
        self.assertEqual(404, e.code)
        self.assertIn(uuid, e.msg)

    def test_share_resource_not_found(self):
        # verify response code for exception.ShareResourceNotFound
        share_id = "fake_share_id"
        e = exception.ShareResourceNotFound(share_id=share_id)
        self.assertEqual(404, e.code)
        self.assertIn(share_id, e.msg)

    def test_share_not_found(self):
        # verify response code for exception.ShareNotFound
        share_id = "fake_share_id"
        e = exception.ShareNotFound(share_id=share_id)
        self.assertEqual(404, e.code)
        self.assertIn(share_id, e.msg)

    def test_resource_lock_not_found(self):
        # verify response code for exception.ResourceLockNotFound
        lock_id = "fake_lock_id"
        e = exception.ResourceLockNotFound(lock_id=lock_id)
        self.assertEqual(404, e.code)
        self.assertIn(lock_id, e.msg)


class ManilaExceptionResponseCode413(test.TestCase):

    def test_quota_error(self):
        # verify response code for exception.QuotaError
        e = exception.QuotaError()
        self.assertEqual(413, e.code)

    def test_share_size_exceeds_available_quota(self):
        # verify response code for exception.ShareSizeExceedsAvailableQuota
        e = exception.ShareSizeExceedsAvailableQuota()
        self.assertEqual(413, e.code)

    def test_share_limit_exceeded(self):
        # verify response code for exception.ShareLimitExceeded
        allowed = 776  # amount of allowed shares
        e = exception.ShareLimitExceeded(allowed=allowed)
        self.assertEqual(413, e.code)
        self.assertIn(str(allowed), e.msg)

    def test_snapshot_limit_exceeded(self):
        # verify response code for exception.SnapshotLimitExceeded
        allowed = 777  # amount of allowed snapshots
        e = exception.SnapshotLimitExceeded(allowed=allowed)
        self.assertEqual(413, e.code)
        self.assertIn(str(allowed), e.msg)

    def test_share_networks_limit_exceeded(self):
        # verify response code for exception.ShareNetworksLimitExceeded
        allowed = 778  # amount of allowed share networks
        e = exception.ShareNetworksLimitExceeded(allowed=allowed)
        self.assertEqual(413, e.code)
        self.assertIn(str(allowed), e.msg)

    def test_port_limit_exceeded(self):
        # verify response code for exception.PortLimitExceeded
        e = exception.PortLimitExceeded()
        self.assertEqual(413, e.code)

    def test_per_share_limit_exceeded(self):
        # verify response code for exception.ShareSizeExceedsLimit
        size = 779  # amount of share size
        limit = 775  # amount of allowed share size limit
        e = exception.ShareSizeExceedsLimit(size=size, limit=limit)
        self.assertEqual(413, e.code)
