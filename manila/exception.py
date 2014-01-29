# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from oslo.config import cfg
import webob.exc


from manila.openstack.common import log as logging

LOG = logging.getLogger(__name__)

exc_log_opts = [
    cfg.BoolOpt('fatal_exception_format_errors',
                default=False,
                help='make exception message format errors fatal'),
]

CONF = cfg.CONF
CONF.register_opts(exc_log_opts)


class ConvertedException(webob.exc.WSGIHTTPException):
    def __init__(self, code=0, title="", explanation=""):
        self.code = code
        self.title = title
        self.explanation = explanation
        super(ConvertedException, self).__init__()


class ProcessExecutionError(IOError):
    def __init__(self, stdout=None, stderr=None, exit_code=None, cmd=None,
                 description=None):
        self.exit_code = exit_code
        self.stderr = stderr
        self.stdout = stdout
        self.cmd = cmd
        self.description = description

        if description is None:
            description = _('Unexpected error while running command.')
        if exit_code is None:
            exit_code = '-'
        message = _('%(description)s\nCommand: %(cmd)s\n'
                    'Exit code: %(exit_code)s\nStdout: %(stdout)r\n'
                    'Stderr: %(stderr)r') % locals()
        IOError.__init__(self, message)


class Error(Exception):
    pass


class DBError(Error):
    """Wraps an implementation specific exception."""
    def __init__(self, inner_exception=None):
        self.inner_exception = inner_exception
        super(DBError, self).__init__(str(inner_exception))


def wrap_db_error(f):
    def _wrap(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except UnicodeEncodeError:
            raise InvalidUnicodeParameter()
        except Exception, e:
            LOG.exception(_('DB exception wrapped.'))
            raise DBError(e)
    _wrap.func_name = f.func_name
    return _wrap


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

    def __init__(self, message=None, **kwargs):
        self.kwargs = kwargs

        if 'code' not in self.kwargs:
            try:
                self.kwargs['code'] = self.code
            except AttributeError:
                pass

        if not message:
            try:
                message = self.message % kwargs

            except Exception as e:
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                LOG.exception(_('Exception in string format operation'))
                for name, value in kwargs.iteritems():
                    LOG.error("%s: %s" % (name, value))
                if CONF.fatal_exception_format_errors:
                    raise e
                else:
                    # at least get the core message out if something happened
                    message = self.message

        self.msg = message
        super(ManilaException, self).__init__(message)


class NetworkException(ManilaException):
    message = _("Exception due to network failure")


class NetworkAllocationException(NetworkException):
    message = _("Failure during network allocation")


class NetworkBadConfigurationException(NetworkException):
    message = _("Bad network configuration: %(reason)s")


class GlanceConnectionFailed(ManilaException):
    message = _("Connection to glance failed") + ": %(reason)s"


class NotAuthorized(ManilaException):
    message = _("Not authorized.")
    code = 403


class AdminRequired(NotAuthorized):
    message = _("User does not have admin privileges")


class PolicyNotAuthorized(NotAuthorized):
    message = _("Policy doesn't allow %(action)s to be performed.")


class ImageNotAuthorized(ManilaException):
    message = _("Not authorized for image %(image_id)s.")


class Invalid(ManilaException):
    message = _("Unacceptable parameters.")
    code = 400


class SfJsonEncodeFailure(ManilaException):
    message = _("Failed to load data into json format")


class InvalidRequest(Invalid):
    message = _("The request is invalid.")


class InvalidResults(Invalid):
    message = _("The results are invalid.")


class InvalidInput(Invalid):
    message = _("Invalid input received") + ": %(reason)s"


class InvalidContentType(Invalid):
    message = _("Invalid content type %(content_type)s.")


class InvalidUnicodeParameter(Invalid):
    message = _("Invalid Parameter: "
                "Unicode is not supported by the current database.")


# Cannot be templated as the error syntax varies.
# msg needs to be constructed when raised.
class InvalidParameterValue(Invalid):
    message = _("%(err)s")


class ServiceUnavailable(Invalid):
    message = _("Service is unavailable at this time.")


class ImageUnacceptable(Invalid):
    message = _("Image %(image_id)s is unacceptable: %(reason)s")


class InvalidUUID(Invalid):
    message = _("Expected a uuid but received %(uuid).")


class NotFound(ManilaException):
    message = _("Resource could not be found.")
    code = 404
    safe = True


class InUse(ManilaException):
    message = _("Resource is in use.")


class ShareNetworkNotFound(NotFound):
    message = _("Network %(share_network_id)s could not be found.")


class InvalidImageRef(Invalid):
    message = _("Invalid image href %(image_href)s.")


class ImageNotFound(NotFound):
    message = _("Image %(image_id)s could not be found.")


class ServiceNotFound(NotFound):
    message = _("Service %(service_id)s could not be found.")


class HostNotFound(NotFound):
    message = _("Host %(host)s could not be found.")


class SchedulerHostFilterNotFound(NotFound):
    message = _("Scheduler Host Filter %(filter_name)s could not be found.")


class SchedulerHostWeigherNotFound(NotFound):
    message = _("Scheduler Host Weigher %(weigher_name)s could not be found.")


class HostBinaryNotFound(NotFound):
    message = _("Could not find binary %(binary)s on host %(host)s.")


class InvalidReservationExpiration(Invalid):
    message = _("Invalid reservation expiration %(expire)s.")


class InvalidQuotaValue(Invalid):
    msg_fmt = _("Change would make usage less than 0 for the following "
                "resources: %(unders)s")


class QuotaNotFound(NotFound):
    msg_fmt = _("Quota could not be found")


class QuotaExists(ManilaException):
    msg_fmt = _("Quota exists for project %(project_id)s, "
                "resource %(resource)s")


class QuotaResourceUnknown(QuotaNotFound):
    msg_fmt = _("Unknown quota resources %(unknown)s.")


class ProjectUserQuotaNotFound(QuotaNotFound):
    msg_fmt = _("Quota for user %(user_id)s in project %(project_id)s "
                "could not be found.")


class ProjectQuotaNotFound(QuotaNotFound):
    msg_fmt = _("Quota for project %(project_id)s could not be found.")


class QuotaClassNotFound(QuotaNotFound):
    msg_fmt = _("Quota class %(class_name)s could not be found.")


class QuotaUsageNotFound(QuotaNotFound):
    msg_fmt = _("Quota usage for project %(project_id)s could not be found.")


class ReservationNotFound(QuotaNotFound):
    msg_fmt = _("Quota reservation %(uuid)s could not be found.")


class OverQuota(ManilaException):
    msg_fmt = _("Quota exceeded for resources: %(overs)s")


class MigrationNotFound(NotFound):
    message = _("Migration %(migration_id)s could not be found.")


class MigrationNotFoundByStatus(MigrationNotFound):
    message = _("Migration not found for instance %(instance_id)s "
                "with status %(status)s.")


class FileNotFound(NotFound):
    message = _("File %(file_path)s could not be found.")


class ClassNotFound(NotFound):
    message = _("Class %(class_name)s could not be found: %(exception)s")


class NotAllowed(ManilaException):
    message = _("Action not allowed.")


#TODO(bcwaldon): EOL this exception!
class Duplicate(ManilaException):
    pass


class KeyPairExists(Duplicate):
    message = _("Key pair %(key_name)s already exists.")


class MigrationError(ManilaException):
    message = _("Migration error") + ": %(reason)s"


class MalformedRequestBody(ManilaException):
    message = _("Malformed message body: %(reason)s")


class ConfigNotFound(NotFound):
    message = _("Could not find config at %(path)s")


class PasteAppNotFound(NotFound):
    message = _("Could not load paste app '%(name)s' from %(path)s")


class NoValidHost(ManilaException):
    message = _("No valid host was found. %(reason)s")


class WillNotSchedule(ManilaException):
    message = _("Host %(host)s is not up or doesn't exist.")


class QuotaError(ManilaException):
    message = _("Quota exceeded") + ": code=%(code)s"
    code = 413
    headers = {'Retry-After': 0}
    safe = True


class ShareSizeExceedsAvailableQuota(QuotaError):
    message = _("Requested share or snapshot exceeds "
                "allowed Gigabytes quota")


class ShareSizeExceedsQuota(QuotaError):
    message = _("Maximum share/snapshot size exceeded")


class ShareLimitExceeded(QuotaError):
    message = _("Maximum number of shares allowed (%(allowed)d) exceeded")


class SnapshotLimitExceeded(QuotaError):
    message = _("Maximum number of snapshots allowed (%(allowed)d) exceeded")


class Duplicate3PARHost(ManilaException):
    message = _("3PAR Host already exists: %(err)s.  %(info)s")


class Invalid3PARDomain(ManilaException):
    message = _("Invalid 3PAR Domain: %(err)s")


class SolidFireAPIException(ManilaException):
    message = _("Bad response from SolidFire API")


class SolidFireAPIDataException(SolidFireAPIException):
    message = _("Error in SolidFire API response: data=%(data)s")


class UnknownCmd(Invalid):
    message = _("Unknown or unsupported command %(cmd)s")


class MalformedResponse(Invalid):
    message = _("Malformed response to command %(cmd)s: %(reason)s")


class BadHTTPResponseStatus(ManilaException):
    message = _("Bad HTTP response status %(status)s")


class FailedCmdWithDump(ManilaException):
    message = _("Operation failed with status=%(status)s. Full dump: %(data)s")


class InstanceNotFound(NotFound):
    message = _("Instance %(instance_id)s could not be found.")


class ShareBackendAPIException(ManilaException):
    message = _("Bad or unexpected response from the storage share "
                "backend API: %(data)s")


class NfsException(ManilaException):
    message = _("Unknown NFS exception")


class NfsNoSharesMounted(NotFound):
    message = _("No mounted NFS shares found")


class NfsNoSuitableShareFound(NotFound):
    message = _("There is no share which can host %(share_size)sG")


class GlusterfsException(ManilaException):
    message = _("Unknown Gluster exception")


class GlusterfsNoSharesMounted(NotFound):
    message = _("No mounted Gluster shares found")


class GlusterfsNoSuitableShareFound(NotFound):
    message = _("There is no share which can host %(share_size)sG")


class ImageCopyFailure(Invalid):
    message = _("Failed to copy image to share")


class InvalidShare(ManilaException):
    message = _("Invalid share: %(reason)s")


class PortLimitExceeded(QuotaError):
    message = _("Maximum number of ports exceeded")


class ShareAccessNotFound(NotFound):
    message = _("Access_id %(access_id)s not found")


class ShareAccessExists(Duplicate):
    message = _("Share access %(access_type)s:%(access)s exists")


class InvalidShareAccess(ManilaException):
    message = _("Invalid access_rule: %(reason)s")


class ShareIsBusy(ManilaException):
    message = _("Deleting $(share_name) share that used")


class ShareBackendException(ManilaException):
    message = _("Share backend error: %(msg)s")


class ShareSnapshotNotFound(NotFound):
    message = _("Snapshot %(snapshot_id)s could not be found.")


class ShareSnapshotIsBusy(ManilaException):
    message = _("Deleting snapshot %(snapshot_name)s that has "
                "dependent shares.")


class InvalidShareSnapshot(ManilaException):
    message = _("Invalid share snapshot: %(reason)s")


class SwiftConnectionFailed(ManilaException):
    message = _("Connection to swift failed") + ": %(reason)s"


class ShareMetadataNotFound(NotFound):
    message = _("Metadata item is not found")


class InvalidShareMetadata(Invalid):
    message = _("Invalid metadata")


class InvalidShareMetadataSize(Invalid):
    message = _("Invalid metadata size")


class SecurityServiceNotFound(NotFound):
    message = _("Security service %(security_service_id)s could not be found.")


class ShareNetworkSecurityServiceAssociationError(ManilaException):
    message = _("Failed to associate share network %(share_network_id)s"
                " and security service %(security_service_id)s: %(reason)s.")


class ShareNetworkSecurityServiceDissociationError(ManilaException):
    message = _("Failed to dissociate share network %(share_network_id)s"
                " and security service %(security_service_id)s: %(reason)s.")


class InvalidShareNetwork(ManilaException):
    message = _("Invalid share network: %(reason)s")


class InvalidVolume(Invalid):
    message = _("Invalid volume.")


class VolumeNotFound(NotFound):
    message = _("Volume %(volume_id)s could not be found.")


class VolumeSnapshotNotFound(NotFound):
    message = _("Snapshot %(snapshot_id)s could not be found.")


class InstanceNotFound(NotFound):
    message = _("Instance %(instance_id)s could not be found.")


class BridgeDoesNotExist(ManilaException):
    message = _("Bridge %(bridge)s does not exist.")
