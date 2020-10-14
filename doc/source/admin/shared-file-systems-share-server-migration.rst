.. _shared_file_systems_share_server_migration:

======================
Share server migration
======================

Share server migration is a functionality that lets administrators migrate
a share server, and all its shares and snapshots, to a new destination.

As with share migration, a 2-phase approach was implemented for share server
migration, which allows to control the right time to complete the operation,
that usually ends on clients disruption.

The process of migrating a share server involves different operations over the
share server, but can be achieved by invoking two main operations: "start" and
"complete". You'll need to begin with the "start" operation and wait until
the service has completed the first phase of the migration to call the
"complete" operation. When a share server is undergoing the first phase, it's
possible to choose to "cancel" it, or get a report of the progress.

A new operation called "migration check" is available to assist on a
pre-migration phase, by validating within the destination host if the
migration can or not be completed, providing an output with the compatible
capabilities supported by the driver.

Share server migration is driven by share drivers, which means
that both source and destination backends must support this functionality,
and the driver must provide such operation in an efficient way.

Server migration workflows
~~~~~~~~~~~~~~~~~~~~~~~~~~

Before actually starting the migration, you can use the operation
:ref:`migration_check <share_server_migration_check_cli>` to verify if the
destination host and the requested capabilities are supported by the driver.
If the answer is ``compatible`` equal to ``True``, you can proceed with the
migration process, otherwise you'll need to identify the conflicting parameters
or, in more complex scenarios, search for messages directly in the manila logs.
The available capabilities are: ``writable``, ``nondisruptive``,
``preserve_snapshots`` and ``new_share_network_id``, which are detailed in
:ref:`shared_file_systems_share_server_migration_parameters`.

The migration process starts by invoking the
:ref:`migration_start <share_server_migration_start_cli>` operation for
a given share server. This operation will start the first phase of the
migration that copies all data, from source to destination, including all
shares, their access rules and even snapshots if supported by the driver
controlling the destination host.

For all ongoing migrations, you can optionally request the current status
of a share server migration using
:ref:`migration_get_progress <share_server_migration_get_progress_cli>`
operation to retrieve the total progress of the data copy and its current task
state. If supported by the driver, you can also cancel this operation by
issuing :ref:`migration_cancel <share_server_migration_cancel_cli>` and wait
until all status become ``active`` and ``available`` again.

After completing the data copy, the first phase is completed and the next
operation, :ref:`migration_complete <share_server_migration_complete_cli>`, can
be initiated to finish the migration.
The :ref:`migration_complete <share_server_migration_complete_cli>` operation
usually disrupts clients access, since the export locations of the shares will
change. The new export locations will be derived from the new share server that
is provisioned at the destination, which is instantiated with distinct network
allocations.

A new field ``task_state`` is available in the share server model to help
track which operation is being executed during this process. The following
tables show, for each phase, the expected ``task_state``, along with their
order of execution and a brief description of the actions that are being
executed in the back end.

.. table:: **Share server migration states - 1st phase**

 ============  ================================  =======================================================================================================================================================
  Sequence      *task_state*                      Description
 ============  ================================  =======================================================================================================================================================
      1          migration_starting               All initial validations passed, all shares and snapshots can't be modified until the end of the migration.
      2          migration_in_progress            The destination host started the process of migration. If the driver doesn't support remain ``writable``, all access rules are modified to read only.
      3          migration_driver_starting        The driver was called to initiate the process of migrating the share server. Manila will wait for driver's answer.
      4          migration_driver_in_progress     The driver accepted the request and started copying the data to the new share server. It will remain in this state until the end of the data copy.
      5          migration_driver_phase1_done     Driver finished copying the data and it's ready to complete the migration.
 ============  ================================  =======================================================================================================================================================

Along with the share server migration progress (in percentage) and the the
current task state, the API also provides the destination share server ID.
Alternatively, you may check the destination share server ID by querying the
share server for a ``source_share_server_id`` set to the ID of the share server
being migrated.
During the entire migration process, the source source share server will remain
with ``server_migrating`` status while the destination share server will remain
with ``server_migrating_to`` status.

If an error occurs during the 1st phase of the migration, the source share
server has its status reverted to ``active`` again, while the destination
server has its status set to ``error``. Both share servers will have their
``task_state`` updated to ``migration_error``. All shares and snapshots are
updated to ``available`` and any ``read-only`` rules are reset to allow writing
into the shares.

.. table:: **Share server migration states - 2nd phase**

 ============  ================================  ========================================================================================================================
  Sequence      *task_state*                      Description
 ============  ================================  ========================================================================================================================
      1          migration_completing             The destination host started processing the operation and the driver is called to complete the share server migration.
      2          migration_success                The migration was completed with success. All shares and snapshots are ``available`` again.
 ============  ================================  ========================================================================================================================

After finishing the share server migration, all shares and snapshots have their
status updated to ``available``. The source share server status is set to
``inactive`` and the destination share server to ``active``.

If an error occurs during the 2nd phase of the migration, both source and
destination share servers will have their status updated to ``error``, along
with their shares and snapshots, since it's not possible to infer if they are
working properly and the current status of the migration. In this scenario,
you will need to manually verify the health of all share server's resources
and manually fix their statuses. Both share servers will have their
``task_state`` set to ``migration_error``.

.. table:: **Share server migration states - migration cancel**

 ============  ================================  =========================================================================================================================================
   Sequence     *task_state*                      Description
 ============  ================================  =========================================================================================================================================
      1          migration_cancel_in_progress     The destination host started the cancel process. It will remain in this state until the driver finishes all tasks that are in progress.
      2          migration_cancelled              The migration was successfully cancelled.
 ============  ================================  =========================================================================================================================================

If an error occurs during the migration cancel operation, the source share
server has its status reverted to ``active`` again, while the destination
server has its status updated to ``error``. Both share servers will have their
``task_state`` set to ``migration_error``. All shares and snapshots have their
statuses updated to ``available``.

Using share server migration CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The available commands to interact with the share server migration API are the
following:

.. _share_server_migration_check_cli:

* ``migration_check``: call a migration check operation to validate if the
  provided destination host is compatible with the requested operation and its
  parameters. The output shows if the destination host is compatible or not and
  the migration capabilities supported by the back end.

  .. code-block:: console

     $ manila share-server-migration-check f3089d4f-89e8-4730-b6e6-7cab553df071 stack@dummy2 --nondisruptive False --writable True --preserve_snapshots True

    +------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Property               | Value                                                                                                                                                                                        |
    +------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | compatible             | True                                                                                                                                                                                         |
    | requested_capabilities | {'writable': 'True', 'nondisruptive': 'False', 'preserve_snapshots': 'True', 'share_network_id': None, 'host': 'stack@dummy2'}                                                               |
    | supported_capabilities | {'writable': True, 'nondisruptive': False, 'preserve_snapshots': True, 'share_network_id': 'ac8e103f-c21a-4442-bddc-fdadee093099', 'migration_cancel': True, 'migration_get_progress': True} |
    +------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

  The ``share_network_id`` attribute in the ``supported_capabilities`` will
  correspond to the value ``--new_share_network`` option if provided, otherwise
  it will be the same as the source share network. In the output it is possible
  to identify if the destination host supports the ``migration_cancel`` and
  ``migration_get_progress`` operations before starting the migration. The
  request parameters are the same for both ``migration_check`` and
  ``migration_start`` operations and are detailed in the following section.

  .. note::
     Back ends might use this operation to do many other validations with
     regards of storage compatibility, free space checks, share-type
     extra-specs validations, and so on. A ``compatible`` equal to ``False``
     answer may not carry the actual conflict. You must check the
     ``manila-share`` logs for more details.

.. _share_server_migration_start_cli:

* ``migration_start``: starts a share server migration to the provided
  destination host. This command starts the 1st phase of the migration that
  is an asynchronous operation and can take long to finish, depending on the
  size of the share server and the efficiency of the storage on copying all
  the data.

  .. code-block:: console

     $ manila share-server-migration-start f3089d4f-89e8-4730-b6e6-7cab553df071 stack@dummy2 --nondisruptive False --writable True --preserve_snapshots True

  The parameters description is detailed in the following section.

  .. note::
     This operation doesn't support migrating share servers with shares that
     have replicas or that belong to share groups.

  .. note::
     The current migration state and progress can be retrieve using the
     ``migration-get-progress`` command.

  .. note::
     This command has no output.

.. _share_server_migration_complete_cli:

* ``migration_complete``: completes a migration that already finished the 1st
  phase. This operation can't be cancelled and might end up on disrupting
  clients' access after all shares migrate to the new share server.

  .. code-block:: console

     $ manila share-server-migration-complete f3089d4f-89e8-4730-b6e6-7cab553df071

    +-----------------------------+--------------------------------------+
    | Property                    | Value                                |
    +-----------------------------+--------------------------------------+
    | destination_share_server_id | f3fb808f-c2a4-4caa-9805-7caaf55c0522 |
    +-----------------------------+--------------------------------------+

.. _share_server_migration_cancel_cli:

* ``migration_cancel``: cancels an in-progress share server migration. This
  operation can only be started while the migration is still on the 1st phase
  of the migration.

  .. code-block:: console

     $ manila share-server-migration-cancel f3089d4f-89e8-4730-b6e6-7cab553df071

  .. note::
     This command has no output.

.. _share_server_migration_get_progress_cli:

* ``migration_get_progress``: obtains the current progress information of a
  share server migration.

  .. code-block:: console

     $ manila share-server-migration-get-progress f3089d4f-89e8-4730-b6e6-7cab553df071

    +-----------------------------+--------------------------------------+
    | Property                    | Value                                |
    +-----------------------------+--------------------------------------+
    | total_progress              | 50                                   |
    | task_state                  | migration_driver_in_progress         |
    | destination_share_server_id | f3fb808f-c2a4-4caa-9805-7caaf55c0522 |
    +-----------------------------+--------------------------------------+

.. _shared_file_systems_share_server_migration_parameters:

Migration check and migration start parameters
----------------------------------------------

Share server :ref:`migration_check <share_server_migration_check_cli>`
and :ref:`migration_start <share_server_migration_start_cli>` operations
have specific parameters that have the semantic detailed below. From these,
only ``new_share_network`` stands as an optional parameter.

* ``share_server_id``: The ID of the share server that will be migrated.

* ``destination_host``: The destination host to which the share server should
  be migrated to, in format ``host@backend``.

* ``preserve_snapshots``: enforces when the preservation of snapshots is
  mandatory for the requested migration. If the destination host doesn't
  support it, the operation will be denied. If this parameter is set to
  ``False``, it will be the driver's supported capability that will define if
  the snapshots will be preserved or not.

  .. note::
     If the driver doesn't support preserving snapshots but at least one share
     has a snapshot, the operation will fail and the you will need to manually
     remove the remaining snapshots before proceeding.

* ``writable``: enforces whether the source share server should remain writable
  for the requested migration. If the destination host doesn't support it,
  the operation will be denied. If this parameter is set to ``False``, it will
  be the driver's supported capability that will define if all shares will
  remain writable or not.

* ``nondisruptive``: enforces whether the migration should keep clients
  connected throughout the migration process. If the destination host doesn't
  support it, the operation will be denied. If this parameter is set to
  ``False``, it will be the driver's supported capability that will define if
  all clients will remain connected or not.

In order to appropriately move a share server to a different host, it may be
required to change the destination share network to be used by the new share
server. In this case, a new share network can be provided using the following
optional parameter:

* ``new_share_network_id``: specifies the ID of the share network that
  should be used when setting up the new share server.

  .. note::
     It is not possible to choose the destination share network subnet since
     it will be automatically selected according to the destination host's
     availability zone. If the new share network doesn't have a share network
     subnet in the destination host's availability zone or doesn't have a
     default subnet, the operation will fail.

Configuration
~~~~~~~~~~~~~

For share server migration to work it is necessary to have compatible back end
stanzas present in the manila configuration of all ``manila-share`` nodes.

Some drivers may provide some driver-specific configuration options that can be
changed to adapt to specific workload. Check :ref:`share_drivers` documentation
for more details.

Important notes
~~~~~~~~~~~~~~~

* Once the migration of a share server has started, the user will see that the
  status of all associated resources change to ``server_migrating`` and
  this will block any other share actions, such as adding or removing access
  rules, creating or deleting snapshots, resizing, among others.

* Since this is a driver-assisted migration, there is no guarantee that the
  destination share server will be cleaned up after a migration failure. For
  this reason, the destination share server will be always updated to ``error``
  if any failure occurs. The same assumption is made for a source share server
  after a successful migration, where manila updates its status to ``inactive``
  to avoid being reused for new shares.

* If a failure occurs during the 2nd phase of the migration, you will need to
  manually identify the current status of the source share server in order to
  revert it back to ``active`` again. If the share server and all its resources
  remain healthy, you will need to reset the status using ``reset_status``
  API for each affected resource.

* Each step in the migration process is saved to the field ``task_state``
  present in the share server model. If for any reason the state is not set to
  ``migration_error`` after a failure, it will need to be reset using the
  ``reset_task_state`` API, to unlock new share actions.

* After a failure occurs, the destination share server will have its status
  updated to ``error`` and will continue pointing to the original source share
  server. This can help you to identify the failed share servers when running
  multiple migrations in parallel.
