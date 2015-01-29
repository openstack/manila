# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 Piston Cloud Computing, Inc.
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
"""
SQLAlchemy models for Manila data.
"""

from oslo_config import cfg
from oslo_db.sqlalchemy import models
from oslo_utils import timeutils
import six
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import orm
from sqlalchemy import ForeignKey, DateTime, Boolean, Enum

from manila.common import constants

CONF = cfg.CONF
BASE = declarative_base()


class ManilaBase(models.ModelBase, models.TimestampMixin):
    """Base class for Manila Models."""
    __table_args__ = {'mysql_engine': 'InnoDB'}
    deleted_at = Column(DateTime)
    deleted = Column(Integer, default=0)
    metadata = None

    def delete(self, session=None):
        """Delete this object."""
        self.deleted = self.id
        self.deleted_at = timeutils.utcnow()
        self.save(session=session)

    def to_dict(self):
        model_dict = {}
        for k, v in six.iteritems(self):
            if not issubclass(type(v), ManilaBase):
                model_dict[k] = v
        return model_dict


class Service(BASE, ManilaBase):
    """Represents a running service on a host."""

    __tablename__ = 'services'
    id = Column(Integer, primary_key=True)
    host = Column(String(255))  # , ForeignKey('hosts.id'))
    binary = Column(String(255))
    topic = Column(String(255))
    report_count = Column(Integer, nullable=False, default=0)
    disabled = Column(Boolean, default=False)
    availability_zone = Column(String(255), default='manila')


class ManilaNode(BASE, ManilaBase):
    """Represents a running manila service on a host."""

    __tablename__ = 'manila_nodes'
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey('services.id'), nullable=True)


class Quota(BASE, ManilaBase):
    """Represents a single quota override for a project.

    If there is no row for a given project id and resource, then the
    default for the quota class is used.  If there is no row for a
    given quota class and resource, then the default for the
    deployment is used. If the row is present but the hard limit is
    Null, then the resource is unlimited.
    """

    __tablename__ = 'quotas'
    id = Column(Integer, primary_key=True)

    project_id = Column(String(255), index=True)

    resource = Column(String(255))
    hard_limit = Column(Integer, nullable=True)


class ProjectUserQuota(BASE, ManilaBase):
    """Represents a single quota override for a user with in a project."""

    __tablename__ = 'project_user_quotas'
    id = Column(Integer, primary_key=True, nullable=False)

    project_id = Column(String(255), nullable=False)
    user_id = Column(String(255), nullable=False)

    resource = Column(String(255), nullable=False)
    hard_limit = Column(Integer)


class QuotaClass(BASE, ManilaBase):
    """Represents a single quota override for a quota class.

    If there is no row for a given quota class and resource, then the
    default for the deployment is used.  If the row is present but the
    hard limit is Null, then the resource is unlimited.
    """

    __tablename__ = 'quota_classes'
    id = Column(Integer, primary_key=True)

    class_name = Column(String(255), index=True)

    resource = Column(String(255))
    hard_limit = Column(Integer, nullable=True)


class QuotaUsage(BASE, ManilaBase):
    """Represents the current usage for a given resource."""

    __tablename__ = 'quota_usages'
    id = Column(Integer, primary_key=True)

    project_id = Column(String(255), index=True)
    user_id = Column(String(255))
    resource = Column(String(255))

    in_use = Column(Integer)
    reserved = Column(Integer)

    @property
    def total(self):
        return self.in_use + self.reserved

    until_refresh = Column(Integer, nullable=True)


class Reservation(BASE, ManilaBase):
    """Represents a resource reservation for quotas."""

    __tablename__ = 'reservations'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), nullable=False)

    usage_id = Column(Integer, ForeignKey('quota_usages.id'), nullable=False)

    project_id = Column(String(255), index=True)
    user_id = Column(String(255))
    resource = Column(String(255))

    delta = Column(Integer)
    expire = Column(DateTime, nullable=False)

#    usage = orm.relationship(
#        "QuotaUsage",
#        foreign_keys=usage_id,
#        primaryjoin='and_(Reservation.usage_id == QuotaUsage.id,'
#                         'QuotaUsage.deleted == 0)')


class Share(BASE, ManilaBase):
    """Represents an NFS and CIFS shares."""
    __tablename__ = 'shares'

    @property
    def name(self):
        return CONF.share_name_template % self.id

    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    user_id = Column(String(255))
    project_id = Column(String(255))
    host = Column(String(255))
    size = Column(Integer)
    availability_zone = Column(String(255))
    status = Column(String(255))
    scheduled_at = Column(DateTime)
    launched_at = Column(DateTime)
    terminated_at = Column(DateTime)
    display_name = Column(String(255))
    display_description = Column(String(255))
    snapshot_id = Column(String(36))
    share_proto = Column(String(255))
    export_location = Column(String(255))
    share_network_id = Column(String(36), ForeignKey('share_networks.id'),
                              nullable=True)
    volume_type_id = Column(String(36), ForeignKey('volume_types.id'),
                            nullable=True)
    share_server_id = Column(String(36), ForeignKey('share_servers.id'),
                             nullable=True)


class VolumeTypes(BASE, ManilaBase):
    """Represent possible volume_types of volumes offered."""
    __tablename__ = "volume_types"
    id = Column(String(36), primary_key=True)
    name = Column(String(255))
    shares = orm.relationship(Share,
                              backref=orm.backref('volume_type',
                                                  uselist=False),
                              foreign_keys=id,
                              primaryjoin='and_('
                              'Share.volume_type_id == VolumeTypes.id, '
                              'VolumeTypes.deleted == False)')


class VolumeTypeExtraSpecs(BASE, ManilaBase):
    """Represents additional specs as key/value pairs for a volume_type."""
    __tablename__ = 'volume_type_extra_specs'
    id = Column(Integer, primary_key=True)
    key = Column(String(255))
    value = Column(String(255))
    volume_type_id = Column(String(36),
                            ForeignKey('volume_types.id'),
                            nullable=False)
    volume_type = orm.relationship(
        VolumeTypes,
        backref="extra_specs",
        foreign_keys=volume_type_id,
        primaryjoin='and_('
        'VolumeTypeExtraSpecs.volume_type_id == VolumeTypes.id,'
        'VolumeTypeExtraSpecs.deleted == False)'
    )


class ShareMetadata(BASE, ManilaBase):
    """Represents a metadata key/value pair for a share."""
    __tablename__ = 'share_metadata'
    id = Column(Integer, primary_key=True)
    key = Column(String(255), nullable=False)
    value = Column(String(1023), nullable=False)
    share_id = Column(String(36), ForeignKey('shares.id'), nullable=False)
    share = orm.relationship(Share, backref="share_metadata",
                             foreign_keys=share_id,
                             primaryjoin='and_('
                             'ShareMetadata.share_id == Share.id,'
                             'ShareMetadata.deleted == 0)')


class ShareAccessMapping(BASE, ManilaBase):
    """Represents access to NFS."""
    STATE_NEW = 'new'
    STATE_ACTIVE = 'active'
    STATE_DELETING = 'deleting'
    STATE_DELETED = 'deleted'
    STATE_ERROR = 'error'

    __tablename__ = 'share_access_map'
    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    share_id = Column(String(36), ForeignKey('shares.id'))
    access_type = Column(String(255))
    access_to = Column(String(255))
    state = Column(Enum(STATE_NEW, STATE_ACTIVE,
                        STATE_DELETING, STATE_DELETED, STATE_ERROR),
                   default=STATE_NEW)
    access_level = Column(Enum(*constants.ACCESS_LEVELS),
                          default=constants.ACCESS_LEVEL_RW)


class ShareSnapshot(BASE, ManilaBase):
    """Represents a snapshot of a share."""
    __tablename__ = 'share_snapshots'

    @property
    def name(self):
        return CONF.share_snapshot_name_template % self.id

    @property
    def share_name(self):
        return CONF.share_name_template % self.share_id

    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    user_id = Column(String(255))
    project_id = Column(String(255))
    share_id = Column(String(36))
    size = Column(Integer)
    status = Column(String(255))
    progress = Column(String(255))
    display_name = Column(String(255))
    display_description = Column(String(255))
    share_size = Column(Integer)
    share_proto = Column(String(255))
    export_location = Column(String(255))
    share = orm.relationship(Share, backref="snapshots",
                             foreign_keys=share_id,
                             primaryjoin='and_('
                             'ShareSnapshot.share_id == Share.id,'
                             'ShareSnapshot.deleted == "False")')


class SecurityService(BASE, ManilaBase):
    """Security service information for manila shares."""

    __tablename__ = 'security_services'
    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    project_id = Column(String(36), nullable=False)
    type = Column(String(32), nullable=False)
    dns_ip = Column(String(64), nullable=True)
    server = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True)
    user = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)
    name = Column(String(255), nullable=True)
    description = Column(String(255), nullable=True)
    status = Column(Enum(constants.STATUS_NEW, constants.STATUS_ACTIVE,
                         constants.STATUS_ERROR),
                    default=constants.STATUS_NEW)


class ShareNetwork(BASE, ManilaBase):
    """Represents network data used by share."""
    __tablename__ = 'share_networks'
    id = Column(String(36), primary_key=True, nullable=False)
    deleted = Column(String(36), default='False')
    project_id = Column(String(36), nullable=False)
    user_id = Column(String(36), nullable=False)
    neutron_net_id = Column(String(36), nullable=True)
    neutron_subnet_id = Column(String(36), nullable=True)
    network_type = Column(String(32), nullable=True)
    segmentation_id = Column(Integer, nullable=True)
    cidr = Column(String(64), nullable=True)
    ip_version = Column(Integer, nullable=True)
    name = Column(String(255), nullable=True)
    description = Column(String(255), nullable=True)
    security_services = orm.relationship(
        "SecurityService",
        secondary="share_network_security_service_association",
        backref="share_networks",
        primaryjoin='and_('
                    'ShareNetwork.id == '
                    'ShareNetworkSecurityServiceAssociation.share_network_id,'
                    'ShareNetworkSecurityServiceAssociation.deleted == 0,'
                    'ShareNetwork.deleted == "False")',
        secondaryjoin='and_('
        'SecurityService.id == '
        'ShareNetworkSecurityServiceAssociation.security_service_id,'
        'SecurityService.deleted == "False")')
    shares = orm.relationship("Share",
                              backref='share_network',
                              primaryjoin='and_('
                              'ShareNetwork.id == Share.share_network_id,'
                              'Share.deleted == "False")')
    share_servers = orm.relationship(
        "ShareServer", backref='share_network',
        primaryjoin='and_(ShareNetwork.id == ShareServer.share_network_id,'
                    'ShareServer.deleted == "False")')


class ShareServer(BASE, ManilaBase):
    """Represents share server used by share."""
    __tablename__ = 'share_servers'
    id = Column(String(36), primary_key=True, nullable=False)
    deleted = Column(String(36), default='False')
    share_network_id = Column(String(36), ForeignKey('share_networks.id'),
                              nullable=True)
    host = Column(String(255), nullable=False)
    status = Column(Enum(constants.STATUS_INACTIVE, constants.STATUS_ACTIVE,
                         constants.STATUS_ERROR, constants.STATUS_DELETING,
                         constants.STATUS_CREATING),
                    default=constants.STATUS_INACTIVE)
    network_allocations = orm.relationship(
        "NetworkAllocation",
        primaryjoin='and_('
                    'ShareServer.id == NetworkAllocation.share_server_id,'
                    'NetworkAllocation.deleted == "False")')
    shares = orm.relationship("Share",
                              backref='share_server',
                              primaryjoin='and_('
                              'ShareServer.id == Share.share_server_id,'
                              'Share.deleted == "False")')


class ShareServerBackendDetails(BASE, ManilaBase):
    """Represents a metadata key/value pair for a share server."""
    __tablename__ = 'share_server_backend_details'
    deleted = Column(String(36), default='False')
    id = Column(Integer, primary_key=True)
    key = Column(String(255), nullable=False)
    value = Column(String(1023), nullable=False)
    share_server_id = Column(String(36), ForeignKey('share_servers.id'),
                             nullable=False)


class ShareNetworkSecurityServiceAssociation(BASE, ManilaBase):
    """Association table between compute_zones and compute_nodes tables."""

    __tablename__ = 'share_network_security_service_association'

    id = Column(Integer, primary_key=True)
    share_network_id = Column(String(36),
                              ForeignKey('share_networks.id'),
                              nullable=False)
    security_service_id = Column(String(36),
                                 ForeignKey('security_services.id'),
                                 nullable=False)


class NetworkAllocation(BASE, ManilaBase):
    """Represents network allocation data."""
    __tablename__ = 'network_allocations'
    id = Column(String(36), primary_key=True, nullable=False)
    deleted = Column(String(36), default='False')
    ip_address = Column(String(64), nullable=True)
    mac_address = Column(String(32), nullable=True)
    share_server_id = Column(String(36), ForeignKey('share_servers.id'),
                             nullable=False)
    status = Column(Enum(constants.STATUS_NEW, constants.STATUS_ACTIVE,
                         constants.STATUS_ERROR),
                    default=constants.STATUS_NEW)


def register_models():
    """Register Models and create metadata.

    Called from manila.db.sqlalchemy.__init__ as part of loading the driver,
    it will never need to be called explicitly elsewhere unless the
    connection is lost and needs to be reestablished.
    """
    from sqlalchemy import create_engine
    models = (Service,
              Share,
              ShareAccessMapping,
              ShareSnapshot
              )
    engine = create_engine(CONF.database.connection, echo=False)
    for model in models:
        model.metadata.create_all(engine)
