======================
Share Server Migration
======================

As of the Victoria release of OpenStack, Manila supports migration of share
servers across different pools through an experimental API. This developer
document reflects the latest version of the experimental Share Server Migration
API.

Feature definition
~~~~~~~~~~~~~~~~~~

The Share Server Migration API is an administrator-only API that allows the
invoker to select a destination backend to migrate a share server to, while
still allowing clients to access the source share server resources during the
migration. Migration of data is expected to be disruptive for users accessing
the source, because at some point it will cease to exist. For this reason, the
share server migration feature is implemented in a 2-phase approach, for the
purpose of controlling the timing of that expected disruption of migrating
share servers.

The first phase of the migration is when operations that take the longest are
performed, such as data copying or replication. After the first phase of data
copying is complete, it is up to the administrator to trigger the second phase,
often referred to as switchover phase, which may perform operations such as a
last sync and changing the source share server to inactive.

During the data copy phase, users remain connected to the source, and may have
to reconnect after the switchover phase.

Share server migration only supports driver-assisted migration. This
mechanism uses the underlying driver running in the manila-share service node
to coordinate the migration. The migration is performed directly in the
storage. In order to use this mechanism, the driver should implement this
functionality. Also, the driver managing the destination back end should
support driver-assisted migration.
Typically, drivers would be able to assist migration of share servers within
storage systems from the same vendor. It is likely that this will be the most
efficient and reliable mechanism to migrate a given share server, as the
storage back end may be able to migrate the share server while remaining
writable, snapshots, and possibly perform this operation non-disruptively.

Note that during a share server migration, access rules cannot be added or
removed. Also, it is not possible to modify existent access rules for
shares and share snapshots created upon the share server being migrated.

API description
~~~~~~~~~~~~~~~

The migration of a share server is started by invoking the
``migration_start`` API. The parameters are:

**share_server_id**
    The share server to be migrated. This parameter is mandatory.

**destination**
    The destination backend in ``host@backend`` representation. This parameter
    is mandatory.

**preserve_snapshots**
    Specifies whether migration should enforce the preservation of all existing
    snapshots at the destination. In other words, the existing snapshots must
    be migrated along with the share server data. When this behavior is
    expected (i.e, this parameter is set to `True`) and drivers are not capable
    of migrating the snapshots, migration will result in an error status.
    This parameter is mandatory.

**nondisruptive**
    Specifies whether the migration should only be performed without disrupting
    clients during migration. For such, it is also expected that the export
    location does not change.  When this behavior is expected (i.e, this
    parameter is set to `True`) and drivers are not capable of allowing the
    share server shares to remain accessible through the two phases of the
    migration, migration will result in an error status. This parameter
    is mandatory.

**writable**
    Specifies whether migration should only be performed if the share server
    shares can remain writable. When this behavior is expected
    (i.e, this parameter is set to `True`) and drivers are not capable of
    allowing the share server shares to remain writable, migration will result
    in an error status. If drivers are not capable of performing a
    nondisruptive migration, manila will ensure that the share server shares
    will remain writable through the data copy phase of migration.
    However, during the switchover phase the shares will be re-exported at the
    destination, causing the share to be rendered inaccessible for the duration
    of this phase. This parameter is mandatory.

**new_share_network_id**
    If willing to change the share server's share-network so it can be
    allocated in the desired destination backend, the invoker may supply a new
    share network to be used. This is often suited when the share server is to
    be migrated to a backend which operates in a different availability zone or
    managed by a driver that handles share servers. This parameter is optional.

After started, a migration may be cancelled through the ``migration_cancel``
API, have its status obtained through the ``migration_get_progress`` API, and
completed through the ``migration_complete`` API after reaching a certain state
(see ``Workflows`` section below).

Workflows
~~~~~~~~~

Upon invoking ``migration_start``, several validations will be performed by
the API layer, such as:

* If supplied API parameters are valid.

* If share server status is `active`.

* If there are share groups related to the share server.

* If a new share network id was provided and is compatible with the
  destination.

* If a new host and share network id were provided and they're different from
  the source share server.

* If the share server to be migrated serves as destination to another share
  server.

* If all the availability zones match with all shares' share types within the
  share server.

* If the share server's shares do not have replicas.

* If the share server's shares are not member of a share group.

* If the access rules of the given share server's shares are not in error
  status.

* If the snapshots of all share server shares are in `available` state.

* If the destination backend chosen to migrate the share server to exists, as
  well as it and its share service are running.

If any of the above validations fail, the API will return an error. Otherwise,
the `task_state` field value will transition to `migration_starting` and the
share server's status will transition to `server_migrating`. Past this point,
all validations, state transitions and errors will not produce any
notifications to the user. Instead, the given share server's `task_state`
field value will transition to `migration_error`.

Right after the API validations, a driver call will be performed in the
destination backend in order to validate if the destination host is compatible
within the requested operation. The driver will then determine the
compatibility between source and destination hosts for the share server
migration.

A new share server will be created in the database, referred to as the
"destination share server", with a status field value `server_migrating_to`.

Share server migration data copy phase
--------------------------------------

A share server will be created as needed at the destination backend. Then, the
share server details are provided to the driver to report the set of migration
capabilities for this destination. If the API parameters `writable`,
`nondisruptive`, `preserve_metadata` and `preserve_snapshots` are satisfied by
the reported migration capabilities, the `task_state` field value transitions
to `migration_driver_starting` and the driver is invoked to start the
migration.

The driver's ``share_server_migration_start`` method should start a job in
the storage back end and return, allowing the `task_state` field value to
transition to `migration_driver_in_progress`. If any of the API parameters
described previously are not satisfied, or the driver raises an exception in
`share_server_migration_start`, the migration ends setting the `task_state`
field value to `migration_error`, and the created share server will have its
status set to error.

Once the ``share_server_migration_start`` driver method succeeds, a periodic
task that checks for shares with `task_state` field value
`migration_driver_in_progress` will invoke the driver's
``share_server_migration_continue`` method, responsible for executing the next
steps of migration until the data copy phase is completed, transitioning the
`task_state` field value to `migration_driver_phase1_done`. If this step fails,
the `task_state` field value transitions to `migration_error` and all allocated
resources will be cleaned up.

Share server migration switchover phase
---------------------------------------

When invoked, the `task_state` field value transitions to
`migration_completing`. In this phase, these operations will happen:
* The source share instances are deleted
* The source share server will have its status set to inactive
* The access rules are applied to the shares of the destination share server
* A final sync is also performed.

At last, the `task_state` field value transitions to
`migration_success`. If the `nondisruptive` capability is not
supported, the export locations will change and clients will need to remount
the shares.

Driver interfaces
~~~~~~~~~~~~~~~~~

All drivers that implement the migration mechanism should be able to perform
all required steps from the source share server back end within the
implementation of the interfaces listed in the section below.
Those steps include:

* Validating compatibility and connectivity between the source and destination
  back end;

* Start the migration job in the storage back end. Return after the job request
  has been submitted;

* Subsequent invocations to the driver to monitor the job status.

* Complete migration by performing a last sync if necessary and delete the
  original shares from the source back end.

.. note::
   The implementation of the ``share_server_migration_cancel`` and
   ``share_server_migration_get_progress`` operations is not mandatory. If the
   driver is able to perform such operations, make sure to set
   ``share_server_migration_cancel`` and
   ``share_server_migration_get_progress`` equal to ``True`` in the response of
   the ``share_server_migration_check`` operation.

Additional notes
~~~~~~~~~~~~~~~~

* In case of an error in the storage back end during the execution of the
  migration job, the driver should raise an exception within the
  ``share_server_migration_continue`` method.

* If the manila-share service is restarted during a migration, the driver's
  ``share_server_migration_continue`` will be invoked periodically with an
  interval configured in the share manager service
  (``share_server_migration_driver_continue_interval``). The invocation
  will stop when the driver finishes the data copy phase.

Share Server Migration interfaces:
----------------------------------

.. autoclass:: manila.share.driver.ShareDriver
    :noindex:
    :members: share_server_migration_check_compatibility, share_server_migration_start, share_server_migration_continue, share_server_migration_complete, share_server_migration_cancel, share_server_migration_get_progress
