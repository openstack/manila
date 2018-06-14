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
from sqlalchemy import Column, Integer, String, schema
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import orm
from sqlalchemy import ForeignKey, DateTime, Boolean, Enum

from manila.common import constants

CONF = cfg.CONF
BASE = declarative_base()


class ManilaBase(models.ModelBase,
                 models.TimestampMixin,
                 models.SoftDeleteMixin):
    """Base class for Manila Models."""
    __table_args__ = {'mysql_engine': 'InnoDB'}
    metadata = None

    def to_dict(self):
        model_dict = {}
        for k, v in self.items():
            if not issubclass(type(v), ManilaBase):
                model_dict[k] = v
        return model_dict

    def soft_delete(self, session, update_status=False,
                    status_field_name='status'):
        """Mark this object as deleted."""
        if update_status:
            setattr(self, status_field_name, constants.STATUS_DELETED)

        return super(ManilaBase, self).soft_delete(session)


class Service(BASE, ManilaBase):
    """Represents a running service on a host."""

    __tablename__ = 'services'
    id = Column(Integer, primary_key=True)
    host = Column(String(255))  # , ForeignKey('hosts.id'))
    binary = Column(String(255))
    topic = Column(String(255))
    report_count = Column(Integer, nullable=False, default=0)
    disabled = Column(Boolean, default=False)
    availability_zone_id = Column(String(36),
                                  ForeignKey('availability_zones.id'),
                                  nullable=True)

    availability_zone = orm.relationship(
        "AvailabilityZone",
        lazy='immediate',
        primaryjoin=(
            'and_('
            'Service.availability_zone_id == '
            'AvailabilityZone.id, '
            'AvailabilityZone.deleted == \'False\')'
        )
    )


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


class ProjectShareTypeQuota(BASE, ManilaBase):
    """Represents a single quota override for a share type within a project."""

    __tablename__ = 'project_share_type_quotas'
    id = Column(Integer, primary_key=True, nullable=False)
    project_id = Column(String(255), nullable=False)
    share_type_id = Column(
        String(36), ForeignKey('share_types.id'), nullable=False)
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
    share_type_id = Column(String(36))
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
    share_type_id = Column(String(36))
    resource = Column(String(255))

    delta = Column(Integer)
    expire = Column(DateTime, nullable=False)


class Share(BASE, ManilaBase):
    """Represents an NFS and CIFS shares."""
    __tablename__ = 'shares'
    _extra_keys = ['name', 'export_location', 'export_locations', 'status',
                   'host', 'share_server_id', 'share_network_id',
                   'availability_zone', 'access_rules_status', 'share_type_id']

    @property
    def name(self):
        return CONF.share_name_template % self.id

    @property
    def export_location(self):
        if len(self.instances) > 0:
            return self.instance.export_location

    @property
    def is_busy(self):
        # Make sure share is not busy, i.e., not part of a migration
        if self.task_state in constants.BUSY_TASK_STATES:
            return True
        return False

    @property
    def export_locations(self):
        # TODO(gouthamr): Return AZ specific export locations for replicated
        # shares.
        # NOTE(gouthamr): For a replicated share, export locations of the
        # 'active' instances are chosen, if 'available'.
        all_export_locations = []
        select_instances = list(filter(
            lambda x: x['replica_state'] == constants.REPLICA_STATE_ACTIVE,
            self.instances)) or self.instances

        for instance in select_instances:
            if instance['status'] == constants.STATUS_AVAILABLE:
                for export_location in instance.export_locations:
                    all_export_locations.append(export_location['path'])

        return all_export_locations

    def __getattr__(self, item):
        proxified_properties = ('status', 'host', 'share_server_id',
                                'share_network_id', 'availability_zone',
                                'share_type_id', 'share_type')

        if item in proxified_properties:
            return getattr(self.instance, item, None)

        raise AttributeError(item)

    @property
    def share_server_id(self):
        return self.__getattr__('share_server_id')

    @property
    def has_replicas(self):
        if len(self.instances) > 1:
            # NOTE(gouthamr): The 'primary' instance of a replicated share
            # has a 'replica_state' set to 'active'. Only the secondary replica
            # instances need to be regarded as true 'replicas' by users.
            replicas = (list(filter(lambda x: x['replica_state'] is not None,
                                    self.instances)))
            return len(replicas) > 1
        return False

    @property
    def instance(self):
        # NOTE(gouthamr): The order of preference: status 'replication_change',
        # followed  by 'available' and 'error'. If replicated share and
        # not undergoing a 'replication_change', only 'active' instances are
        # preferred.
        result = None
        if len(self.instances) > 0:
            order = (constants.STATUS_REVERTING,
                     constants.STATUS_REPLICATION_CHANGE,
                     constants.STATUS_MIGRATING, constants.STATUS_AVAILABLE,
                     constants.STATUS_ERROR)
            other_statuses = (
                [x['status'] for x in self.instances if
                 x['status'] not in order and
                 x['status'] not in constants.TRANSITIONAL_STATUSES]
            )
            order = (order + tuple(other_statuses) +
                     constants.TRANSITIONAL_STATUSES)
            sorted_instances = sorted(
                self.instances, key=lambda x: order.index(x['status']))

            select_instances = sorted_instances
            if (select_instances[0]['status'] !=
                    constants.STATUS_REPLICATION_CHANGE):
                select_instances = (
                    list(filter(lambda x: x['replica_state'] ==
                                constants.REPLICA_STATE_ACTIVE,
                                sorted_instances)) or sorted_instances
                )
            result = select_instances[0]
        return result

    @property
    def access_rules_status(self):
        return get_access_rules_status(self.instances)

    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    user_id = Column(String(255))
    project_id = Column(String(255))
    size = Column(Integer)

    display_name = Column(String(255))
    display_description = Column(String(255))
    snapshot_id = Column(String(36))
    snapshot_support = Column(Boolean, default=True)
    create_share_from_snapshot_support = Column(Boolean, default=True)
    revert_to_snapshot_support = Column(Boolean, default=False)
    replication_type = Column(String(255), nullable=True)
    mount_snapshot_support = Column(Boolean, default=False)
    share_proto = Column(String(255))
    is_public = Column(Boolean, default=False)
    share_group_id = Column(String(36),
                            ForeignKey('share_groups.id'),
                            nullable=True)

    source_share_group_snapshot_member_id = Column(String(36), nullable=True)
    task_state = Column(String(255))
    instances = orm.relationship(
        "ShareInstance",
        lazy='immediate',
        primaryjoin=(
            'and_('
            'Share.id == ShareInstance.share_id, '
            'ShareInstance.deleted == "False")'
        ),
        viewonly=True,
        join_depth=2,
    )


class ShareInstance(BASE, ManilaBase):
    __tablename__ = 'share_instances'

    _extra_keys = ['name', 'export_location', 'availability_zone',
                   'replica_state']
    _proxified_properties = ('user_id', 'project_id', 'size',
                             'display_name', 'display_description',
                             'snapshot_id', 'share_proto', 'is_public',
                             'share_group_id', 'replication_type',
                             'source_share_group_snapshot_member_id',
                             'mount_snapshot_support')

    def set_share_data(self, share):
        for share_property in self._proxified_properties:
            setattr(self, share_property, share[share_property])

    @property
    def name(self):
        return CONF.share_name_template % self.id

    @property
    def export_location(self):
        if len(self.export_locations) > 0:
            return self.export_locations[0]['path']

    @property
    def availability_zone(self):
        if self._availability_zone:
            return self._availability_zone['name']

    id = Column(String(36), primary_key=True)
    share_id = Column(String(36), ForeignKey('shares.id'))
    deleted = Column(String(36), default='False')
    host = Column(String(255))
    status = Column(String(255))

    ACCESS_STATUS_PRIORITIES = {
        constants.STATUS_ACTIVE: 0,
        constants.SHARE_INSTANCE_RULES_SYNCING: 1,
        constants.SHARE_INSTANCE_RULES_ERROR: 2,
    }

    access_rules_status = Column(Enum(constants.STATUS_ACTIVE,
                                      constants.SHARE_INSTANCE_RULES_SYNCING,
                                      constants.SHARE_INSTANCE_RULES_ERROR),
                                 default=constants.STATUS_ACTIVE)

    scheduled_at = Column(DateTime)
    launched_at = Column(DateTime)
    terminated_at = Column(DateTime)
    replica_state = Column(String(255), nullable=True)
    cast_rules_to_readonly = Column(Boolean, default=False, nullable=False)
    share_type_id = Column(String(36), ForeignKey('share_types.id'),
                           nullable=True)
    availability_zone_id = Column(String(36),
                                  ForeignKey('availability_zones.id'),
                                  nullable=True)
    _availability_zone = orm.relationship(
        "AvailabilityZone",
        lazy='immediate',
        foreign_keys=availability_zone_id,
        primaryjoin=(
            'and_('
            'ShareInstance.availability_zone_id == '
            'AvailabilityZone.id, '
            'AvailabilityZone.deleted == \'False\')'
        )
    )

    export_locations = orm.relationship(
        "ShareInstanceExportLocations",
        lazy='immediate',
        primaryjoin=(
            'and_('
            'ShareInstance.id == '
            'ShareInstanceExportLocations.share_instance_id, '
            'ShareInstanceExportLocations.deleted == 0)'
        )
    )
    share_network_id = Column(String(36), ForeignKey('share_networks.id'),
                              nullable=True)
    share_server_id = Column(String(36), ForeignKey('share_servers.id'),
                             nullable=True)
    share_type = orm.relationship(
        "ShareTypes",
        lazy='immediate',
        foreign_keys=share_type_id,
        primaryjoin='and_('
                    'ShareInstance.share_type_id == ShareTypes.id, '
                    'ShareTypes.deleted == "False")')


class ShareInstanceExportLocations(BASE, ManilaBase):
    """Represents export locations of share instances."""
    __tablename__ = 'share_instance_export_locations'

    _extra_keys = ['el_metadata', ]

    @property
    def el_metadata(self):
        el_metadata = {}
        for meta in self._el_metadata_bare:  # pylint: disable=E1101
            el_metadata[meta['key']] = meta['value']
        return el_metadata

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), nullable=False, unique=True)
    share_instance_id = Column(
        String(36), ForeignKey('share_instances.id'), nullable=False)
    path = Column(String(2000))
    is_admin_only = Column(Boolean, default=False, nullable=False)


class ShareInstanceExportLocationsMetadata(BASE, ManilaBase):
    """Represents export location metadata of share instances."""
    __tablename__ = "share_instance_export_locations_metadata"

    _extra_keys = ['export_location_uuid', ]

    id = Column(Integer, primary_key=True)
    export_location_id = Column(
        Integer,
        ForeignKey("share_instance_export_locations.id"), nullable=False)
    key = Column(String(255), nullable=False)
    value = Column(String(1023), nullable=False)
    export_location = orm.relationship(
        ShareInstanceExportLocations,
        backref="_el_metadata_bare",
        foreign_keys=export_location_id,
        lazy='immediate',
        primaryjoin="and_("
                    "%(cls_name)s.export_location_id == "
                    "ShareInstanceExportLocations.id,"
                    "%(cls_name)s.deleted == 0)" % {
                        "cls_name": "ShareInstanceExportLocationsMetadata"})

    @property
    def export_location_uuid(self):
        return self.export_location.uuid  # pylint: disable=E1101


class ShareTypes(BASE, ManilaBase):
    """Represent possible share_types of volumes offered."""
    __tablename__ = "share_types"
    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    name = Column(String(255))
    description = Column(String(255))
    is_public = Column(Boolean, default=True)


class ShareTypeProjects(BASE, ManilaBase):
    """Represent projects associated share_types."""
    __tablename__ = "share_type_projects"
    __table_args__ = (schema.UniqueConstraint(
        "share_type_id", "project_id", "deleted",
        name="uniq_share_type_projects0share_type_id0project_id0deleted"),
    )
    id = Column(Integer, primary_key=True)
    share_type_id = Column(Integer, ForeignKey('share_types.id'),
                           nullable=False)
    project_id = Column(String(255))

    share_type = orm.relationship(
        ShareTypes,
        backref="projects",
        foreign_keys=share_type_id,
        primaryjoin='and_('
                    'ShareTypeProjects.share_type_id == ShareTypes.id,'
                    'ShareTypeProjects.deleted == 0)')


class ShareTypeExtraSpecs(BASE, ManilaBase):
    """Represents additional specs as key/value pairs for a share_type."""
    __tablename__ = 'share_type_extra_specs'
    id = Column(Integer, primary_key=True)
    key = Column("spec_key", String(255))
    value = Column("spec_value", String(255))
    share_type_id = Column(String(36), ForeignKey('share_types.id'),
                           nullable=False)
    share_type = orm.relationship(
        ShareTypes,
        backref="extra_specs",
        foreign_keys=share_type_id,
        primaryjoin='and_('
        'ShareTypeExtraSpecs.share_type_id == ShareTypes.id,'
        'ShareTypeExtraSpecs.deleted == 0)'
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
    """Represents access to share."""
    __tablename__ = 'share_access_map'

    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    share_id = Column(String(36), ForeignKey('shares.id'))
    access_type = Column(String(255))
    access_to = Column(String(255))
    access_key = Column(String(255), nullable=True)

    access_level = Column(Enum(*constants.ACCESS_LEVELS),
                          default=constants.ACCESS_LEVEL_RW)

    @property
    def state(self):
        """Get the aggregated 'state' from all the instance mapping states.

        An access rule is supposed to be truly 'active' when it has been
        applied across all of the share instances of the parent share object.
        """
        return get_aggregated_access_rules_state(self.instance_mappings)

    instance_mappings = orm.relationship(
        "ShareInstanceAccessMapping",
        lazy='immediate',
        primaryjoin=(
            'and_('
            'ShareAccessMapping.id == '
            'ShareInstanceAccessMapping.access_id, '
            'ShareInstanceAccessMapping.deleted == "False")'
        )
    )


class ShareInstanceAccessMapping(BASE, ManilaBase):
    """Represents access to individual share instances."""

    __tablename__ = 'share_instance_access_map'
    _proxified_properties = ('share_id', 'access_type', 'access_key',
                             'access_to', 'access_level')

    def set_share_access_data(self, share_access):
        for share_access_attr in self._proxified_properties:
            setattr(self, share_access_attr, share_access[share_access_attr])

    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    share_instance_id = Column(String(36), ForeignKey('share_instances.id'))
    access_id = Column(String(36), ForeignKey('share_access_map.id'))
    state = Column(String(255), default=constants.ACCESS_STATE_QUEUED_TO_APPLY)

    instance = orm.relationship(
        "ShareInstance",
        lazy='immediate',
        primaryjoin=(
            'and_('
            'ShareInstanceAccessMapping.share_instance_id == '
            'ShareInstance.id, '
            'ShareInstanceAccessMapping.deleted == "False")'
        )
    )


class ShareSnapshot(BASE, ManilaBase):
    """Represents a snapshot of a share."""
    __tablename__ = 'share_snapshots'
    _extra_keys = ['name', 'share_name', 'status', 'progress',
                   'provider_location', 'aggregate_status']

    def __getattr__(self, item):
        proxified_properties = ('status', 'progress', 'provider_location')

        if item in proxified_properties:
            return getattr(self.instance, item, None)

        raise AttributeError(item)

    @property
    def export_locations(self):
        # TODO(gouthamr): Return AZ specific export locations for replicated
        # snapshots.
        # NOTE(gouthamr): For a replicated snapshot, export locations of the
        # 'active' instances are chosen, if 'available'.
        all_export_locations = []
        select_instances = list(filter(
            lambda x: (x['share_instance']['replica_state'] ==
                       constants.REPLICA_STATE_ACTIVE),
            self.instances)) or self.instances

        for instance in select_instances:
            if instance['status'] == constants.STATUS_AVAILABLE:
                for export_location in instance.export_locations:
                    all_export_locations.append(export_location)

        return all_export_locations

    @property
    def name(self):
        return CONF.share_snapshot_name_template % self.id

    @property
    def share_name(self):
        return CONF.share_name_template % self.share_id

    @property
    def instance(self):
        result = None
        if len(self.instances) > 0:
            def qualified_replica(x):
                preferred_statuses = (constants.REPLICA_STATE_ACTIVE,)
                return x['replica_state'] in preferred_statuses

            replica_snapshots = list(filter(
                lambda x: qualified_replica(x.share_instance), self.instances))

            migrating_snapshots = list(filter(
                lambda x: x.share_instance['status'] ==
                constants.STATUS_MIGRATING, self.instances))

            snapshot_instances = (replica_snapshots or migrating_snapshots
                                  or self.instances)

            result = snapshot_instances[0]

        return result

    @property
    def aggregate_status(self):
        """Get the aggregated 'status' of all instances.

        A snapshot is supposed to be truly 'available' when it is available
        across all of the share instances of the parent share object. In
        case of replication, we only consider replicas (share instances)
        that are in 'in_sync' replica_state.
        """

        def qualified_replica(x):
            preferred_statuses = (constants.REPLICA_STATE_ACTIVE,
                                  constants.REPLICA_STATE_IN_SYNC)
            return x['replica_state'] in preferred_statuses

        replica_snapshots = list(filter(
            lambda x: qualified_replica(x['share_instance']), self.instances))

        if not replica_snapshots:
            return self.status

        order = (constants.STATUS_DELETING, constants.STATUS_CREATING,
                 constants.STATUS_ERROR, constants.STATUS_MIGRATING,
                 constants.STATUS_AVAILABLE)
        other_statuses = [x['status'] for x in self.instances if
                          x['status'] not in order]
        order = (order + tuple(other_statuses))

        sorted_instances = sorted(
            replica_snapshots, key=lambda x: order.index(x['status']))
        return sorted_instances[0].status

    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    user_id = Column(String(255))
    project_id = Column(String(255))
    share_id = Column(String(36))
    size = Column(Integer)
    display_name = Column(String(255))
    display_description = Column(String(255))
    share_size = Column(Integer)
    share_proto = Column(String(255))
    share = orm.relationship(Share, backref="snapshots",
                             foreign_keys=share_id,
                             primaryjoin='and_('
                             'ShareSnapshot.share_id == Share.id,'
                             'ShareSnapshot.deleted == "False")')


class ShareSnapshotInstance(BASE, ManilaBase):
    """Represents a snapshot of a share."""
    __tablename__ = 'share_snapshot_instances'
    _extra_keys = ['name', 'share_id', 'share_name']

    @property
    def name(self):
        return CONF.share_snapshot_name_template % self.id

    @property
    def share_name(self):
        return CONF.share_name_template % self.share_instance_id

    @property
    def share_id(self):
        # NOTE(u_glide): This property required for compatibility
        # with share drivers
        return self.share_instance_id

    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    snapshot_id = Column(String(36), nullable=True)
    share_instance_id = Column(
        String(36), ForeignKey('share_instances.id'), nullable=False)
    status = Column(String(255))
    progress = Column(String(255))
    provider_location = Column(String(255))
    share_proto = Column(String(255))
    size = Column(Integer)
    share_group_snapshot_id = Column(String(36), nullable=True)
    user_id = Column(String(255))
    project_id = Column(String(255))

    export_locations = orm.relationship(
        "ShareSnapshotInstanceExportLocation",
        lazy='immediate',
        primaryjoin=(
            'and_('
            'ShareSnapshotInstance.id == '
            'ShareSnapshotInstanceExportLocation.share_snapshot_instance_id, '
            'ShareSnapshotInstanceExportLocation.deleted == "False")'
        )
    )
    share_instance = orm.relationship(
        ShareInstance, backref="snapshot_instances",
        lazy='immediate',
        primaryjoin=(
            'and_('
            'ShareSnapshotInstance.share_instance_id == ShareInstance.id,'
            'ShareSnapshotInstance.deleted == "False")')
    )
    snapshot = orm.relationship(
        "ShareSnapshot",
        lazy="immediate",
        foreign_keys=snapshot_id,
        backref="instances",
        primaryjoin=(
            'and_('
            'ShareSnapshot.id == ShareSnapshotInstance.snapshot_id, '
            'ShareSnapshotInstance.deleted == "False")'
        ),
        viewonly=True,
        join_depth=2,
    )
    share_group_snapshot = orm.relationship(
        "ShareGroupSnapshot",
        lazy="immediate",
        foreign_keys=share_group_snapshot_id,
        backref="share_group_snapshot_members",
        primaryjoin=('ShareGroupSnapshot.id == '
                     'ShareSnapshotInstance.share_group_snapshot_id'),
        viewonly=True,
        join_depth=2,
    )


class ShareSnapshotAccessMapping(BASE, ManilaBase):
    """Represents access to share snapshot."""
    __tablename__ = 'share_snapshot_access_map'

    @property
    def state(self):
        """Get the aggregated 'state' from all the instance mapping states.

        An access rule is supposed to be truly 'active' when it has been
        applied across all of the share snapshot instances of the parent
        share snapshot object.
        """
        return get_aggregated_access_rules_state(self.instance_mappings)

    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    share_snapshot_id = Column(String(36), ForeignKey('share_snapshots.id'))
    access_type = Column(String(255))
    access_to = Column(String(255))

    instance_mappings = orm.relationship(
        "ShareSnapshotInstanceAccessMapping",
        lazy='immediate',
        primaryjoin=(
            'and_('
            'ShareSnapshotAccessMapping.id == '
            'ShareSnapshotInstanceAccessMapping.access_id, '
            'ShareSnapshotInstanceAccessMapping.deleted == "False")'
        )
    )


class ShareSnapshotInstanceAccessMapping(BASE, ManilaBase):
    """Represents access to individual share snapshot instances."""

    __tablename__ = 'share_snapshot_instance_access_map'
    _proxified_properties = ('share_snapshot_id', 'access_type', 'access_to')

    def set_snapshot_access_data(self, snapshot_access):
        for snapshot_access_attr in self._proxified_properties:
            setattr(self, snapshot_access_attr,
                    snapshot_access[snapshot_access_attr])

    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    share_snapshot_instance_id = Column(String(36), ForeignKey(
        'share_snapshot_instances.id'))
    access_id = Column(String(36), ForeignKey('share_snapshot_access_map.id'))
    state = Column(Enum(*constants.ACCESS_RULES_STATES),
                   default=constants.ACCESS_STATE_QUEUED_TO_APPLY)

    instance = orm.relationship(
        "ShareSnapshotInstance",
        lazy='immediate',
        primaryjoin=(
            'and_('
            'ShareSnapshotInstanceAccessMapping.share_snapshot_instance_id == '
            'ShareSnapshotInstance.id, '
            'ShareSnapshotInstanceAccessMapping.deleted == "False")'
        )
    )


class ShareSnapshotInstanceExportLocation(BASE, ManilaBase):
    """Represents export locations of share snapshot instances."""
    __tablename__ = 'share_snapshot_instance_export_locations'

    id = Column(String(36), primary_key=True)
    share_snapshot_instance_id = Column(
        String(36), ForeignKey('share_snapshot_instances.id'), nullable=False)
    path = Column(String(2000))
    is_admin_only = Column(Boolean, default=False, nullable=False)
    deleted = Column(String(36), default='False')


class SecurityService(BASE, ManilaBase):
    """Security service information for manila shares."""

    __tablename__ = 'security_services'
    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    project_id = Column(String(255), nullable=False)
    type = Column(String(32), nullable=False)
    dns_ip = Column(String(64), nullable=True)
    server = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True)
    user = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)
    name = Column(String(255), nullable=True)
    description = Column(String(255), nullable=True)


class ShareNetwork(BASE, ManilaBase):
    """Represents network data used by share."""
    __tablename__ = 'share_networks'
    id = Column(String(36), primary_key=True, nullable=False)
    deleted = Column(String(36), default='False')
    project_id = Column(String(255), nullable=False)
    user_id = Column(String(255), nullable=False)
    neutron_net_id = Column(String(36), nullable=True)
    neutron_subnet_id = Column(String(36), nullable=True)
    network_type = Column(String(32), nullable=True)
    segmentation_id = Column(Integer, nullable=True)
    cidr = Column(String(64), nullable=True)
    gateway = Column(String(64), nullable=True)
    mtu = Column(Integer, nullable=True)
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
    share_instances = orm.relationship(
        "ShareInstance",
        backref='share_network',
        primaryjoin='and_('
                    'ShareNetwork.id == ShareInstance.share_network_id,'
                    'ShareInstance.deleted == "False")')
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
                         constants.STATUS_CREATING, constants.STATUS_DELETED),
                    default=constants.STATUS_INACTIVE)
    network_allocations = orm.relationship(
        "NetworkAllocation",
        primaryjoin='and_('
                    'ShareServer.id == NetworkAllocation.share_server_id,'
                    'NetworkAllocation.deleted == "False")')
    share_instances = orm.relationship(
        "ShareInstance",
        backref='share_server',
        primaryjoin='and_('
                    'ShareServer.id == ShareInstance.share_server_id,'
                    'ShareInstance.deleted == "False")')

    share_groups = orm.relationship(
        "ShareGroup", backref='share_server', primaryjoin='and_('
        'ShareServer.id == ShareGroup.share_server_id,'
        'ShareGroup.deleted == "False")')

    _backend_details = orm.relationship(
        "ShareServerBackendDetails",
        lazy='immediate',
        viewonly=True,
        primaryjoin='and_('
                    'ShareServer.id == '
                    'ShareServerBackendDetails.share_server_id, '
                    'ShareServerBackendDetails.deleted == "False")')

    @property
    def backend_details(self):
        return {model['key']: model['value']
                for model in self._backend_details}

    _extra_keys = ['backend_details']


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
    label = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)
    ip_version = Column(Integer, nullable=True)
    cidr = Column(String(64), nullable=True)
    gateway = Column(String(64), nullable=True)
    mtu = Column(Integer, nullable=True)
    network_type = Column(String(32), nullable=True)
    segmentation_id = Column(Integer, nullable=True)
    mac_address = Column(String(32), nullable=True)
    share_server_id = Column(String(36), ForeignKey('share_servers.id'),
                             nullable=False)


class DriverPrivateData(BASE, ManilaBase):
    """Represents a private data as key-value pairs for a driver."""
    __tablename__ = 'drivers_private_data'
    entity_uuid = Column(String(36), nullable=False, primary_key=True)
    key = Column(String(255), nullable=False, primary_key=True)
    value = Column(String(1023), nullable=False)


class AvailabilityZone(BASE, ManilaBase):
    """Represents a private data as key-value pairs for a driver."""
    __tablename__ = 'availability_zones'
    id = Column(String(36), primary_key=True, nullable=False)
    deleted = Column(String(36), default='False')
    name = Column(String(255), nullable=False)


class ShareGroupTypes(BASE, ManilaBase):
    """Represent possible share group types of shares offered."""
    __tablename__ = "share_group_types"
    __table_args__ = (
        schema.UniqueConstraint(
            "name", "deleted", name="uniq_share_group_type_name"),
    )
    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    name = Column(String(255))
    is_public = Column(Boolean, default=True)


class ShareGroup(BASE, ManilaBase):
    """Represents a share group."""
    __tablename__ = 'share_groups'
    _extra_keys = [
        'availability_zone',
    ]
    id = Column(String(36), primary_key=True)
    user_id = Column(String(255), nullable=False)
    project_id = Column(String(255), nullable=False)
    deleted = Column(String(36), default='False')
    host = Column(String(255))
    name = Column(String(255))
    description = Column(String(255))
    status = Column(String(255))
    source_share_group_snapshot_id = Column(String(36))
    share_network_id = Column(
        String(36), ForeignKey('share_networks.id'), nullable=True)
    share_server_id = Column(
        String(36), ForeignKey('share_servers.id'), nullable=True)
    share_group_type_id = Column(
        String(36), ForeignKey('share_group_types.id'), nullable=True)
    availability_zone_id = Column(
        String(36), ForeignKey('availability_zones.id'), nullable=True)
    consistent_snapshot_support = Column(Enum('pool', 'host'), default=None)

    share_group_type = orm.relationship(
        ShareGroupTypes,
        backref="share_groups",
        foreign_keys=share_group_type_id,
        primaryjoin='and_('
                    'ShareGroup.share_group_type_id == '
                    'ShareGroupTypes.id,'
                    'ShareGroup.deleted == 0)')
    _availability_zone = orm.relationship(
        "AvailabilityZone",
        lazy='immediate',
        foreign_keys=availability_zone_id,
        primaryjoin=(
            "and_("
            "ShareGroup.availability_zone_id == AvailabilityZone.id, "
            "AvailabilityZone.deleted == 'False')"))

    @property
    def availability_zone(self):
        if self._availability_zone:
            return self._availability_zone['name']


class ShareGroupTypeProjects(BASE, ManilaBase):
    """Represent projects associated share group types."""
    __tablename__ = "share_group_type_projects"
    __table_args__ = (schema.UniqueConstraint(
        "share_group_type_id", "project_id", "deleted",
        name=("uniq_share_group_type_projects0share_group_type_id"
              "0project_id0deleted")),
    )
    id = Column(Integer, primary_key=True)
    share_group_type_id = Column(
        String, ForeignKey('share_group_types.id'), nullable=False)
    project_id = Column(String(255))
    share_group_type = orm.relationship(
        ShareGroupTypes,
        backref="projects",
        foreign_keys=share_group_type_id,
        primaryjoin='and_('
                    'ShareGroupTypeProjects.share_group_type_id == '
                    'ShareGroupTypes.id,'
                    'ShareGroupTypeProjects.deleted == 0)')


class ShareGroupTypeSpecs(BASE, ManilaBase):
    """Represents additional specs for a share group type."""
    __tablename__ = 'share_group_type_specs'
    id = Column(Integer, primary_key=True)
    key = Column("spec_key", String(255))
    value = Column("spec_value", String(255))
    share_group_type_id = Column(
        String(36), ForeignKey('share_group_types.id'), nullable=False)
    share_group_type = orm.relationship(
        ShareGroupTypes,
        backref="group_specs",
        foreign_keys=share_group_type_id,
        primaryjoin='and_('
        'ShareGroupTypeSpecs.share_group_type_id == ShareGroupTypes.id,'
        'ShareGroupTypeSpecs.deleted == 0)'
    )


class ShareGroupSnapshot(BASE, ManilaBase):
    """Represents a share group snapshot."""
    __tablename__ = 'share_group_snapshots'
    id = Column(String(36), primary_key=True)
    share_group_id = Column(String(36), ForeignKey('share_groups.id'))
    user_id = Column(String(255), nullable=False)
    project_id = Column(String(255), nullable=False)
    deleted = Column(String(36), default='False')
    name = Column(String(255))
    description = Column(String(255))
    status = Column(String(255))
    share_group = orm.relationship(
        ShareGroup,
        backref="snapshots",
        foreign_keys=share_group_id,
        primaryjoin=('and_('
                     'ShareGroupSnapshot.share_group_id == ShareGroup.id,'
                     'ShareGroupSnapshot.deleted == "False")')
    )


class ShareGroupTypeShareTypeMapping(BASE, ManilaBase):
    """Represents the share types supported by a share group type."""
    __tablename__ = 'share_group_type_share_type_mappings'
    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    share_group_type_id = Column(
        String(36), ForeignKey('share_group_types.id'), nullable=False)
    share_type_id = Column(
        String(36), ForeignKey('share_types.id'), nullable=False)
    share_group_type = orm.relationship(
        ShareGroupTypes,
        backref="share_types",
        foreign_keys=share_group_type_id,
        primaryjoin=('and_('
                     'ShareGroupTypeShareTypeMapping.share_group_type_id '
                     '== ShareGroupTypes.id,'
                     'ShareGroupTypeShareTypeMapping.deleted == "False")')
    )


class ShareGroupShareTypeMapping(BASE, ManilaBase):
    """Represents the share types in a share group."""
    __tablename__ = 'share_group_share_type_mappings'
    id = Column(String(36), primary_key=True)
    deleted = Column(String(36), default='False')
    share_group_id = Column(
        String(36), ForeignKey('share_groups.id'), nullable=False)
    share_type_id = Column(
        String(36), ForeignKey('share_types.id'), nullable=False)
    share_group = orm.relationship(
        ShareGroup,
        backref="share_types",
        foreign_keys=share_group_id,
        primaryjoin=('and_('
                     'ShareGroupShareTypeMapping.share_group_id '
                     '== ShareGroup.id,'
                     'ShareGroupShareTypeMapping.deleted == "False")')
    )


class Message(BASE, ManilaBase):
    """Represents a user message.

    User messages show information about API operations to the API end-user.
    """
    __tablename__ = 'messages'
    id = Column(String(36), primary_key=True, nullable=False)
    project_id = Column(String(255), nullable=False)
    # Info/Error/Warning.
    message_level = Column(String(255), nullable=False)
    request_id = Column(String(255), nullable=True)
    resource_type = Column(String(255))
    # The uuid of the related resource.
    resource_id = Column(String(36), nullable=True)
    # Operation specific action ID, this ID is mapped
    # to a message in manila/message/message_field.py
    action_id = Column(String(10), nullable=False)
    # After this time the message may no longer exist.
    expires_at = Column(DateTime, nullable=True)
    # Message detail ID, this ID is mapped
    # to a message in manila/message/message_field.py
    detail_id = Column(String(10), nullable=True)
    deleted = Column(String(36), default='False')


class BackendInfo(BASE, ManilaBase):
    """Represent Backend Info."""
    __tablename__ = "backend_info"
    host = Column(String(255), primary_key=True)
    info_hash = Column(String(255))


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


def get_access_rules_status(instances):
    share_access_status = constants.STATUS_ACTIVE

    if len(instances) == 0:
        return share_access_status

    priorities = ShareInstance.ACCESS_STATUS_PRIORITIES

    for instance in instances:
        if instance['status'] != constants.STATUS_AVAILABLE:
            continue

        instance_access_status = instance['access_rules_status']

        if priorities.get(instance_access_status) > priorities.get(
                share_access_status):
            share_access_status = instance_access_status

        if share_access_status == constants.SHARE_INSTANCE_RULES_ERROR:
            break

    return share_access_status


def get_aggregated_access_rules_state(instance_mappings):
    state = None
    if len(instance_mappings) > 0:
        order = (constants.ACCESS_STATE_ERROR,
                 constants.ACCESS_STATE_DENYING,
                 constants.ACCESS_STATE_QUEUED_TO_DENY,
                 constants.ACCESS_STATE_QUEUED_TO_APPLY,
                 constants.ACCESS_STATE_APPLYING,
                 constants.ACCESS_STATE_ACTIVE)

        sorted_instance_mappings = sorted(
            instance_mappings, key=lambda x: order.index(x['state']))

        state = sorted_instance_mappings[0].state
    return state
