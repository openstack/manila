..
      Copyright (c) 2016 Hitachi Data Systems

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


===============
Share Migration
===============

As of the Ocata release of OpenStack, :term:`manila` supports migration of
shares across different pools through an experimental API. Since it was first
introduced, several enhancements have been made through the subsequent
releases while still in experimental state. This developer document reflects
the latest version of the experimental Share Migration API.

Feature definition
~~~~~~~~~~~~~~~~~~

The Share Migration API is an administrator-only experimental API that allows
the invoker to select a destination pool to migrate a share to, while still
allowing clients to access the source share instance during the migration.
Migration of data is generally expected to be disruptive for users accessing
the source, because at some point it will cease to exist. For this reason,
the share migration feature is implemented in a 2-phase approach, for the
purpose of controlling the timing of that expected disruption of migrating
shares.

The first phase of migration is when operations that take the longest are
performed, such as data copying or replication. After the first pass of data
copying is complete, it is up to the administrator to trigger the second phase,
often referred to as switchover phase, which may perform operations such as a
last sync and deleting the source share instance.

During the data copy phase, users remain connected to the source, and may have
to reconnect after the switchover phase. In order to migrate a share, manila
may employ one of two mechanisms which provide different capabilities and
affect how the disruption occurs with regards to user access during data copy
phase and disconnection during switchover phase. Those two mechanisms are:

**driver-assisted migration**
    This mechanism uses the underlying driver running in the manila-share
    service node to coordinate the migration. The migration itself is performed
    directly on the storage. In order for this mechanism to be used, it
    requires the driver to implement this functionality, while also requiring
    that the driver which manages the destination pool is compatible with
    driver-assisted migration. Typically, drivers would be able to assist
    migration of shares within storage systems from the same vendor. It is
    likely that this will be the most efficient and reliable mechanism to
    migrate a given share, as the storage back end may be able to migrate the
    share while remaining writable, preserving all file system metadata,
    snapshots, and possibly perform this operation non-disruptively. When this
    mechanism cannot be used, the host-assisted migration will be attempted.

**host-assisted migration**
    This mechanism uses the Data Service (manila-data) to copy the source
    share's data to a new destination share created in the given destination
    pool. For this mechanism to work, it is required that the Data Service is
    properly configured in the cloud environment and the migration operation
    for the source share's protocol and access rule type combination is
    supported by the Data Service. This is the most suited mechanism to migrate
    shares when the two pools are from different storage vendors. Given that
    this mechanism is a rough copy of files and the back ends are unaware that
    their share contents are being copied over, the optimizations found in the
    driver-assisted migration are not present here, thus the source share
    remains read-only, snapshots cannot be transferred, some file system
    metadata such as permissions and ownership may be lost, and users are
    expected to be disconnected by the end of migration.

Note that during a share migration, access rules cannot be added or removed.

As of Ocata release, this feature allows several concurrent migrations
(driver-assisted or host-assisted) to be performed, having a best-effort type
of scalability.

API description
~~~~~~~~~~~~~~~

The migration of a share is started by invoking the ``migration_start`` API.
The parameters are:

**share**
    The share to be migrated. This parameter is mandatory.

**destination**
    The destination pool in ``host@backend#pool`` representation. This
    parameter is mandatory.

**force_host_assisted_migration**
    Forces the host-assisted mechanism to be used, thus using the Data Service
    to copy data across back ends. This parameter value defaults to `False`.
    When set to `True`, it skips the driver-assisted approach which would
    otherwise be attempted first. This parameter is optional.

**preserve_metadata**
    Specifies whether migration should enforce the preservation of all file
    system metadata. When this behavior is expected (i.e, this parameter is set
    to `True`) and drivers are not capable of ensuring preservation of file
    system metadata, migration will result in an error status. As of Ocata
    release, host-assisted migration cannot provide any guarantees of
    preserving file system metadata. This parameter is mandatory.

**preserve_snapshots**
    Specifies whether migration should enforce the preservation of all existing
    snapshots at the destination. In other words, the existing snapshots must
    be migrated along with the share data. When this behavior is expected (i.e,
    this parameter is set to `True`) and drivers are not capable of migrating
    the snapshots, migration will result in an error status. As of Ocata
    release, host-assisted migration cannot provide this capability. This
    parameter is mandatory.

**nondisruptive**
    Specifies whether migration should only be performed without disrupting
    clients during migration. For such, it is also expected that the export
    location does not change.  When this behavior is expected (i.e, this
    parameter is set to `True`) and drivers are not capable of allowing the
    share to remain accessible through the two phases of the migration,
    migration will result in an error status. As of Ocata release,
    host-assisted migration cannot provide this capability. This parameter is
    mandatory.

**writable**
    Specifies whether migration should only be performed if the share can
    remain writable. When this behavior is expected (i.e, this parameter is set
    to `True`) and drivers are not capable of allowing the share to remain
    writable, migration will result in an error status. If drivers are not
    capable of performing a nondisruptive migration, manila will ensure that
    the share will remain writable through the data copy phase of migration.
    However, during the switchover phase the share will be re-exported at the
    destination, causing the share to be rendered inaccessible for the duration
    of this phase. As of Ocata release, host-assisted migration cannot provide
    this capability. This parameter is mandatory.

**new_share_type**
    If willing to retype the share so it can be allocated in the desired
    destination pool, the invoker may supply a new share type to be used. This
    is often suited when the share is to be migrated to a pool which operates
    in the opposite driver mode. This parameter is optional.

**new_share_network**
    If willing to change the share's share-network so it can be allocated in
    the desired destination pool, the invoker may supply a new share network to
    be used. This is often suited when the share is to be migrated to a pool
    which operates in a different availability zone or managed by a driver that
    handles share servers. This parameter is optional.

After started, a migration may be cancelled through the ``migration_cancel``
API, have its status obtained through the ``migration_get_progress`` API, and
completed through the ``migration_complete`` API after reaching a certain
state (see ``Workflows`` section below).

Workflows
~~~~~~~~~

Upon invoking ``migration_start``, several validations will be performed by the
API layer, such as:

* If supplied API parameters are valid.

* If the share does not have replicas.

* If the share is not member of a share group.

* If the access rules of the given share are not in error status.

* If the driver-assisted parameters specified do not conflict with
  `force_host_assisted_migration` parameter.

* If `force_host_assisted_migration` parameter is set to True while snapshots
  do not exist.

* If share status is `available` and is not busy with other tasks.

* If the destination pool chosen to migrate the share to exists and is
  running.

* If share service or Data Service responsible for performing the migration
  exists and is running.

* If the combination of share network and share type resulting is compatible
  with regards to driver modes.

If any of the above validations fail, the API will return an error. Otherwise,
the `task_state` field value will transition to `migration_starting` and the
share's status will transition to `migrating`. Past this point, all
validations, state transitions and errors will not produce any notifications to
the user. Instead, the given share's `task_state` field value will transition
to `migration_error`.

Following API validation, the scheduler will validate if the supplied
destination is compatible with the desired share type according to the pool's
capabilities. If this validation fails, the `task_state` field value will
transition to `migration_error`.

The scheduler then invokes the source share pool's manager to proceed with the
migration, transitioning the `task_state` field value to
`migration_in_progress`. If `force-host-assisted-migration` API parameter is
not set, then a driver-assisted migration will be attempted first.

Note that whichever mechanism is employed, there will be a new share instance
created in the database, referred to as the "destination instance", with a
status field value `migrating_to`. This share instance will not have its
export location displayed during migration and will prevail instead of the
original instance database entry when migration is complete.

Driver-assisted migration data copy phase
-----------------------------------------

A share server will be created as needed at the destination pool. Then, the
share server details are provided to the driver to report the set of migration
capabilities for this destination. If the API parameters `writable`,
`nondisruptive`, `preserve_metadata` and `preserve_snapshots` are satisfied by
the reported migration capabilities, the `task_state` field value transitions
to `migration_driver_starting` and the driver is invoked to start the
migration.

The driver's migration_start method should start a job in the storage back end
and return, allowing the `task_state` field value to transition to
`migration_driver_in_progress`. If any of the API parameters described
previously are not satisfied, or the driver raises an exception in
`migration_start`, the driver-assisted migration ends setting the `task_state`
field value to `migration_error`, all allocated resources will be cleaned up
and migration will proceed to the host-assisted migration mechanism.

Once the `migration_start` driver method succeeds, a periodic task that checks
for shares with `task_state` field value `migration_driver_in_progress` will
invoke the driver's `migration_continue` method, responsible for executing the
next steps of migration until the data copy phase is completed, transitioning
the `task_state` field value to `migration_driver_phase1_done`. If this step
fails, the `task_state` field value transitions to `migration_error` and all
allocated resources will be cleaned up.

Host-assisted migration data copy phase
---------------------------------------

A new share will be created at the destination pool and the source share's
access rules will be changed to read-only. The `task_state` field value
transitions to `data_copying_starting` and the Data Service is then invoked to
mount both shares and copy data from the source to the destination.

In order for the Data Service to mount the shares, it will ask the storage
driver to allow access to the node where the Data Service is running. It will
then attempt to mount the shares via their respective administrator-only export
locations that are served in the administrator network when available,
otherwise the regular export locations will be used.

In order for the access and mount procedures to succeed, the administrator-only
export location must be reachable from the Data Service and the access
parameter properly configured in the Data Service configuration file. For
instance, a NFS share should require an IP configuration, whereas a CIFS share
should require a username credential. Those parameters should be previously
set in the Data Service configuration file by the administrator.

The data copy routine runs commands as root user for the purpose of setting the
correct file metadata to the newly created files at the destination share. It
can optionally verify the integrity of all files copied through a configuration
parameter. Once copy is completed, the shares are unmounted, their access
from the Data Service are removed and the `task_state` field value transitions
to `data_copying_completed`, allowing the switchover phase to be invoked.

Share migration switchover phase
--------------------------------

When invoked, the `task_state` field value transitions to
`migration_completing`. Whichever migration mechanism is used, the source share
instance is deleted and the access rules are applied to the destination share
instance. In the driver-assisted migration, the driver is first invoked to
perform a final sync.

The last step is to update the share model's optional capability fields, such
as `create_share_from_snapshot_support`, `revert_to_snapshot_support` and
`mount_snapshot_support`, according to the `new_share_type`, if it had been
specified when the migration was initiated.

At last, the `task_state` field value transitions to
`migration_success`. If the `nondisruptive` driver-assisted capability is not
supported or the host-assisted migration mechanism is used, the export location
will change and clients will need to remount the share.

Driver interfaces
~~~~~~~~~~~~~~~~~

All drivers that implement the driver-assisted migration mechanism should be
able to perform all required steps from the source share instance back end
within the implementation of the interfaces listed in the section below.
Those steps include:

* Validating compatibility and connectivity between the source and destination
  back end;

* Start the migration job in the storage back end. Return after the job request
  has been submitted;

* Subsequent invocations to the driver to monitor the job status, cancel it and
  obtain its progress in percentage value;

* Complete migration by performing a last sync if necessary and delete the
  original share from the source back end.

For host-assisted migration, drivers may override some methods defined in the
base class in case it is necessary to support it.

Additional notes
~~~~~~~~~~~~~~~~

* In case of an error in the storage back end during the execution of the
  migration job, the driver should raise an exception within the
  ``migration_continue`` method.

* If the manila-share service is restarted during a migration, in case it is a
  driver-assisted migration, the driver's ``migration_continue`` will be
  invoked continuously with an interval configured in the share manager service
  (``migration_driver_continue_interval``). The invocation will stop when the
  driver finishes the data copy phase. In case of host-assisted migration, the
  migration job is disrupted only if the manila-data service is restarted. In
  such event, the migration has to be restarted from the beginning.

* To be compatible with host-assisted migration, drivers must also support
  the ``update_access`` interface, along with its `recovery mode` mechanism.

Share Migration driver-assisted interfaces:
-------------------------------------------

.. autoclass:: manila.share.driver.ShareDriver
    :noindex:
    :members: migration_check_compatibility, migration_start, migration_continue, migration_complete, migration_cancel, migration_get_progress

Share Migration host-assisted interfaces:
-----------------------------------------

.. autoclass:: manila.share.driver.ShareDriver
    :noindex:
    :members:  connection_get_info
