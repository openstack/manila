# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Manila base exception handling.

Includes decorator for re-raising Manila-type exceptions.

SHOULD include dedicated exception logging.

"""
import re

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
import six
import webob.exc

from manila.i18n import _
from manila.i18n import _LE

LOG = log.getLogger(__name__)

exc_log_opts = [
    cfg.BoolOpt('fatal_exception_format_errors',
                default=False,
                help='Whether to make exception message format errors fatal.'),
]

CONF = cfg.CONF
CONF.register_opts(exc_log_opts)


ProcessExecutionError = processutils.ProcessExecutionError


class ConvertedException(webob.exc.WSGIHTTPException):
    def __init__(self, code=400, title="", explanation=""):
        self.code = code
        self.title = title
        self.explanation = explanation
        super(ConvertedException, self).__init__()


class Error(Exception):
    pass


class ManilaException(Exception):
    """Base Manila Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.

    """
    message = _("An unknown exception occurred.")
    code = 500
    headers = {}
    safe = False

    def __init__(self, message=None, detail_data={}, **kwargs):
        self.kwargs = kwargs
        self.detail_data = detail_data

        if 'code' not in self.kwargs:
            try:
                self.kwargs['code'] = self.code
            except AttributeError:
                pass
        for k, v in self.kwargs.items():
            if isinstance(v, Exception):
                self.kwargs[k] = six.text_type(v)

        if not message:
            try:
                message = self.message % kwargs

            except Exception as e:
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                LOG.exception(_LE('Exception in string format operation.'))
                for name, value in kwargs.items():
                    LOG.error(_LE("%(name)s: %(value)s"), {
                        'name': name, 'value': value})
                if CONF.fatal_exception_format_errors:
                    raise e
                else:
                    # at least get the core message out if something happened
                    message = self.message
        elif isinstance(message, Exception):
            message = six.text_type(message)

        if re.match('.*[^\.]\.\.$', message):
            message = message[:-1]
        self.msg = message
        super(ManilaException, self).__init__(message)


class NetworkException(ManilaException):
    message = _("Exception due to network failure.")


class NetworkBadConfigurationException(NetworkException):
    message = _("Bad network configuration: %(reason)s.")


class NotAuthorized(ManilaException):
    message = _("Not authorized.")
    code = 403


class AdminRequired(NotAuthorized):
    message = _("User does not have admin privileges.")


class PolicyNotAuthorized(NotAuthorized):
    message = _("Policy doesn't allow %(action)s to be performed.")


class Conflict(ManilaException):
    message = _("%(err)s")
    code = 409


class Invalid(ManilaException):
    message = _("Unacceptable parameters.")
    code = 400


class InvalidRequest(Invalid):
    message = _("The request is invalid.")


class InvalidResults(Invalid):
    message = _("The results are invalid.")


class InvalidInput(Invalid):
    message = _("Invalid input received: %(reason)s.")


class InvalidContentType(Invalid):
    message = _("Invalid content type %(content_type)s.")


class InvalidHost(Invalid):
    message = _("Invalid host: %(reason)s")


# Cannot be templated as the error syntax varies.
# msg needs to be constructed when raised.
class InvalidParameterValue(Invalid):
    message = _("%(err)s")


class InvalidUUID(Invalid):
    message = _("Expected a uuid but received %(uuid)s.")


class InvalidDriverMode(Invalid):
    message = _("Invalid driver mode: %(driver_mode)s.")


class InvalidAPIVersionString(Invalid):
    message = _("API Version String %(version)s is of invalid format. Must "
                "be of format MajorNum.MinorNum.")


class VersionNotFoundForAPIMethod(Invalid):
    message = _("API version %(version)s is not supported on this method.")


class InvalidGlobalAPIVersion(Invalid):
    message = _("Version %(req_ver)s is not supported by the API. Minimum "
                "is %(min_ver)s and maximum is %(max_ver)s.")


class InvalidCapacity(Invalid):
    message = _("Invalid capacity: %(name)s = %(value)s.")


class NotFound(ManilaException):
    message = _("Resource could not be found.")
    code = 404
    safe = True


class InUse(ManilaException):
    message = _("Resource is in use.")


class AvailabilityZoneNotFound(NotFound):
    message = _("Availability zone %(id)s could not be found.")


class ShareNetworkNotFound(NotFound):
    message = _("Share network %(share_network_id)s could not be found.")


class ShareServerNotFound(NotFound):
    message = _("Share server %(share_server_id)s could not be found.")


class ShareServerNotFoundByFilters(ShareServerNotFound):
    message = _("Share server could not be found by "
                "filters: %(filters_description)s.")


class ShareServerInUse(InUse):
    message = _("Share server %(share_server_id)s is in use.")


class InvalidShareServer(Invalid):
    message = _("Share server %(share_server_id)s is not valid.")


class ShareMigrationFailed(ManilaException):
    message = _("Share migration failed: %(reason)s")


class ServiceIPNotFound(ManilaException):
    message = _("Share migration failed: %(reason)s")


class ShareServerNotCreated(ManilaException):
    message = _("Share server %(share_server_id)s failed on creation.")


class ServiceNotFound(NotFound):
    message = _("Service %(service_id)s could not be found.")


class ServiceIsDown(Invalid):
    message = _("Service %(service)s is down.")


class HostNotFound(NotFound):
    message = _("Host %(host)s could not be found.")


class SchedulerHostFilterNotFound(NotFound):
    message = _("Scheduler host filter %(filter_name)s could not be found.")


class SchedulerHostWeigherNotFound(NotFound):
    message = _("Scheduler host weigher %(weigher_name)s could not be found.")


class HostBinaryNotFound(NotFound):
    message = _("Could not find binary %(binary)s on host %(host)s.")


class InvalidReservationExpiration(Invalid):
    message = _("Invalid reservation expiration %(expire)s.")


class InvalidQuotaValue(Invalid):
    message = _("Change would make usage less than 0 for the following "
                "resources: %(unders)s.")


class QuotaNotFound(NotFound):
    message = _("Quota could not be found.")


class QuotaExists(ManilaException):
    message = _("Quota exists for project %(project_id)s, "
                "resource %(resource)s.")


class QuotaResourceUnknown(QuotaNotFound):
    message = _("Unknown quota resources %(unknown)s.")


class ProjectUserQuotaNotFound(QuotaNotFound):
    message = _("Quota for user %(user_id)s in project %(project_id)s "
                "could not be found.")


class ProjectQuotaNotFound(QuotaNotFound):
    message = _("Quota for project %(project_id)s could not be found.")


class QuotaClassNotFound(QuotaNotFound):
    message = _("Quota class %(class_name)s could not be found.")


class QuotaUsageNotFound(QuotaNotFound):
    message = _("Quota usage for project %(project_id)s could not be found.")


class ReservationNotFound(QuotaNotFound):
    message = _("Quota reservation %(uuid)s could not be found.")


class OverQuota(ManilaException):
    message = _("Quota exceeded for resources: %(overs)s.")


class MigrationNotFound(NotFound):
    message = _("Migration %(migration_id)s could not be found.")


class MigrationNotFoundByStatus(MigrationNotFound):
    message = _("Migration not found for instance %(instance_id)s "
                "with status %(status)s.")


class FileNotFound(NotFound):
    message = _("File %(file_path)s could not be found.")


class MigrationError(ManilaException):
    message = _("Migration error: %(reason)s.")


class MalformedRequestBody(ManilaException):
    message = _("Malformed message body: %(reason)s.")


class ConfigNotFound(NotFound):
    message = _("Could not find config at %(path)s.")


class PasteAppNotFound(NotFound):
    message = _("Could not load paste app '%(name)s' from %(path)s.")


class NoValidHost(ManilaException):
    message = _("No valid host was found. %(reason)s.")


class WillNotSchedule(ManilaException):
    message = _("Host %(host)s is not up or doesn't exist.")


class QuotaError(ManilaException):
    message = _("Quota exceeded: code=%(code)s.")
    code = 413
    headers = {'Retry-After': 0}
    safe = True


class ShareSizeExceedsAvailableQuota(QuotaError):
    message = _("Requested share exceeds allowed gigabytes quota.")


class SnapshotSizeExceedsAvailableQuota(QuotaError):
    message = _("Requested snapshot exceeds allowed gigabytes quota.")


class ShareLimitExceeded(QuotaError):
    message = _("Maximum number of shares allowed (%(allowed)d) exceeded.")


class SnapshotLimitExceeded(QuotaError):
    message = _("Maximum number of snapshots allowed (%(allowed)d) exceeded.")


class ShareNetworksLimitExceeded(QuotaError):
    message = _("Maximum number of share-networks "
                "allowed (%(allowed)d) exceeded.")


class GlusterfsException(ManilaException):
    message = _("Unknown Gluster exception.")


class InvalidShare(Invalid):
    message = _("Invalid share: %(reason)s.")


class ShareBusyException(Invalid):
    message = _("Share is busy with an active task: %(reason)s.")


class InvalidShareInstance(Invalid):
    message = _("Invalid share instance: %(reason)s.")


class ManageInvalidShare(InvalidShare):
    message = _("Manage existing share failed due to "
                "invalid share: %(reason)s")


class UnmanageInvalidShare(InvalidShare):
    message = _("Unmanage existing share failed due to "
                "invalid share: %(reason)s")


class PortLimitExceeded(QuotaError):
    message = _("Maximum number of ports exceeded.")


class ShareAccessExists(ManilaException):
    message = _("Share access %(access_type)s:%(access)s exists.")


class InvalidShareAccess(Invalid):
    message = _("Invalid access rule: %(reason)s")


class InvalidShareAccessLevel(Invalid):
    message = _("Invalid or unsupported share access level: %(level)s.")


class ShareBackendException(ManilaException):
    message = _("Share backend error: %(msg)s.")


class ExportLocationNotFound(NotFound):
    message = _("Export location %(uuid)s could not be found.")


class ShareSnapshotNotFound(NotFound):
    message = _("Snapshot %(snapshot_id)s could not be found.")


class ShareSnapshotNotSupported(ManilaException):
    message = _("Share %(share_name)s does not support snapshots.")


class ShareSnapshotIsBusy(ManilaException):
    message = _("Deleting snapshot %(snapshot_name)s that has "
                "dependent shares.")


class InvalidShareSnapshot(Invalid):
    message = _("Invalid share snapshot: %(reason)s.")


class ShareMetadataNotFound(NotFound):
    message = _("Metadata item is not found.")


class InvalidShareMetadata(Invalid):
    message = _("Invalid metadata.")


class InvalidShareMetadataSize(Invalid):
    message = _("Invalid metadata size.")


class SecurityServiceNotFound(NotFound):
    message = _("Security service %(security_service_id)s could not be found.")


class ShareNetworkSecurityServiceAssociationError(ManilaException):
    message = _("Failed to associate share network %(share_network_id)s"
                " and security service %(security_service_id)s: %(reason)s.")


class ShareNetworkSecurityServiceDissociationError(ManilaException):
    message = _("Failed to dissociate share network %(share_network_id)s"
                " and security service %(security_service_id)s: %(reason)s.")


class InvalidVolume(Invalid):
    message = _("Invalid volume.")


class InvalidShareType(Invalid):
    message = _("Invalid share type: %(reason)s.")


class InvalidExtraSpec(Invalid):
    message = _("Invalid extra_spec: %(reason)s.")


class VolumeNotFound(NotFound):
    message = _("Volume %(volume_id)s could not be found.")


class VolumeSnapshotNotFound(NotFound):
    message = _("Snapshot %(snapshot_id)s could not be found.")


class ShareTypeNotFound(NotFound):
    message = _("Share type %(share_type_id)s could not be found.")


class ShareTypeAccessNotFound(NotFound):
    message = _("Share type access not found for %(share_type_id)s / "
                "%(project_id)s combination.")


class ShareTypeNotFoundByName(ShareTypeNotFound):
    message = _("Share type with name %(share_type_name)s "
                "could not be found.")


class ShareTypeExtraSpecsNotFound(NotFound):
    message = _("Share Type %(share_type_id)s has no extra specs with "
                "key %(extra_specs_key)s.")


class ShareTypeInUse(ManilaException):
    message = _("Share Type %(share_type_id)s deletion is not allowed with "
                "shares present with the type.")


class ShareTypeExists(ManilaException):
    message = _("Share Type %(id)s already exists.")


class ShareTypeAccessExists(ManilaException):
    message = _("Share type access for %(share_type_id)s / "
                "%(project_id)s combination already exists.")


class ShareTypeCreateFailed(ManilaException):
    message = _("Cannot create share_type with "
                "name %(name)s and specs %(extra_specs)s.")


class ManageExistingShareTypeMismatch(ManilaException):
    message = _("Manage existing share failed due to share type mismatch: "
                "%(reason)s")


class ShareExtendingError(ManilaException):
    message = _("Share %(share_id)s could not be extended due to error "
                "in the driver: %(reason)s")


class ShareShrinkingError(ManilaException):
    message = _("Share %(share_id)s could not be shrunk due to error "
                "in the driver: %(reason)s")


class ShareShrinkingPossibleDataLoss(ManilaException):
    message = _("Share %(share_id)s could not be shrunk due to "
                "possible data loss")


class InstanceNotFound(NotFound):
    message = _("Instance %(instance_id)s could not be found.")


class BridgeDoesNotExist(ManilaException):
    message = _("Bridge %(bridge)s does not exist.")


class ServiceInstanceException(ManilaException):
    message = _("Exception in service instance manager occurred.")


class ServiceInstanceUnavailable(ServiceInstanceException):
    message = _("Service instance is not available.")


class StorageResourceException(ManilaException):
    message = _("Storage resource exception.")


class StorageResourceNotFound(StorageResourceException):
    message = _("Storage resource %(name)s not found.")
    code = 404


class SnapshotNotFound(StorageResourceNotFound):
    message = _("Snapshot %(name)s not found.")


class SnapshotUnavailable(StorageResourceException):
    message = _("Snapshot %(name)s info not available.")


class NetAppException(ManilaException):
    message = _("Exception due to NetApp failure.")


class VserverNotFound(NetAppException):
    message = _("Vserver %(vserver)s not found.")


class VserverNotSpecified(NetAppException):
    message = _("Vserver not specified.")


class EMCVnxXMLAPIError(Invalid):
    message = _("%(err)s")


class EMCVnxLockRequiredException(ManilaException):
    message = _("Unable to acquire lock(s).")


class EMCVnxInvalidMoverID(ManilaException):
    message = _("Invalid mover or vdm %(id)s.")


class HPE3ParInvalidClient(Invalid):
    message = _("%(err)s")


class HPE3ParInvalid(Invalid):
    message = _("%(err)s")


class HPE3ParUnexpectedError(ManilaException):
    message = _("%(err)s")


class GPFSException(ManilaException):
    message = _("GPFS exception occurred.")


class GPFSGaneshaException(ManilaException):
    message = _("GPFS Ganesha exception occurred.")


class GaneshaCommandFailure(ProcessExecutionError):
    _description = _("Ganesha management command failed.")

    def __init__(self, **kw):
        if 'description' not in kw:
            kw['description'] = self._description
        super(GaneshaCommandFailure, self).__init__(**kw)


class InvalidSqliteDB(Invalid):
    message = _("Invalid Sqlite database.")


class SSHException(ManilaException):
    message = _("Exception in SSH protocol negotiation or logic.")


class HDFSException(ManilaException):
    message = _("HDFS exception occurred!")


class QBException(ManilaException):
    message = _("Quobyte exception occurred: %(msg)s")


class QBRpcException(ManilaException):
    """Quobyte backend specific exception."""
    message = _("Quobyte JsonRpc call to backend raised "
                "an exception: %(result)s, Quobyte error"
                " code %(qbcode)s")


class SSHInjectionThreat(ManilaException):
    message = _("SSH command injection detected: %(command)s")


class HNASBackendException(ManilaException):
    message = _("HNAS Backend Exception: %(msg)s")


class HNASConnException(ManilaException):
    message = _("HNAS Connection Exception: %(msg)s")


class HNASItemNotFoundException(StorageResourceNotFound):
    message = _("HNAS Item Not Found Exception: %(msg)s")


class HNASNothingToCloneException(ManilaException):
    message = _("HNAS Nothing To Clone Exception: %(msg)s")


# ConsistencyGroup
class ConsistencyGroupNotFound(NotFound):
    message = _("ConsistencyGroup %(consistency_group_id)s could not be "
                "found.")


class CGSnapshotNotFound(NotFound):
    message = _("Consistency group snapshot %(cgsnapshot_id)s could not be "
                "found.")


class CGSnapshotMemberNotFound(NotFound):
    message = _("CG snapshot %(member_id)s could not be found.")


class InvalidConsistencyGroup(Invalid):
    message = _("Invalid ConsistencyGroup: %(reason)s")


class InvalidCGSnapshot(Invalid):
    message = _("Invalid CGSnapshot: %(reason)s")


class DriverNotInitialized(ManilaException):
    message = _("Share driver '%(driver)s' not initialized.")


class ShareResourceNotFound(StorageResourceNotFound):
    message = _("Share id %(share_id)s could not be found "
                "in storage backend.")


class ShareUmountException(ManilaException):
    message = _("Failed to unmount share: %(reason)s")


class ShareMountException(ManilaException):
    message = _("Failed to mount share: %(reason)s")


class ShareCopyDataException(ManilaException):
    message = _("Failed to copy data: %(reason)s")


# Replication
class ReplicationException(ManilaException):
    message = _("Unable to perform a replication action: %(reason)s.")


class ShareReplicaNotFound(NotFound):
    message = _("Share Replica %(replica_id)s could not be found.")
