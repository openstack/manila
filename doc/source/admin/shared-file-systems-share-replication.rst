.. _shared_file_systems_share_replication:

=================
Share replication
=================


Replication of data has a number of use cases in the cloud. One use case is
High Availability of the data in a shared file system, used for example, to
support a production database. Another use case is ensuring Data Protection;
i.e being prepared for a disaster by having a replication location that will be
ready to back up your primary data source.

The Shared File System service supports user facing APIs that allow users to
create shares that support replication, add and remove share replicas and
manage their snapshots and access rules. Three replication types are currently
supported and they vary in the semantics associated with the primary share and
the secondary copies.

.. note::

   **Share replication** APIs were introduced in the Mitaka release and
   graduated from experimental status in API version 2.56. Starting from
   version 2.56, these APIs are stable and no longer require the
   ``X-OpenStack-Manila-API-Experimental`` header. For API versions 2.11
   through 2.55, the experimental header is still required for backward
   compatibility.


Replication types supported
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before using share replication, make sure the Shared File System driver that
you are running supports this feature. You can check it in the
``manila-scheduler`` service reports. The ``replication_type`` capability
reported can have one of the following values:

writable
   The driver supports creating ``writable`` share replicas. All share replicas
   can be accorded read/write access and would be synchronously mirrored.
readable
   The driver supports creating ``read-only`` share replicas. All secondary
   share replicas can be accorded read access. Only the primary (or ``active``
   share replica) can be written into.
dr
   The driver supports creating ``dr`` (abbreviated from Disaster Recovery)
   share replicas. A secondary share replica is inaccessible until after a
   ``promotion``.
None
   The driver does not support Share Replication.


.. note::

   The term ``active`` share replica refers to the ``primary`` share. In
   ``writable`` style of replication, all share replicas are ``active``, and
   there could be no distinction of a ``primary`` share. In ``readable`` and
   ``dr`` styles of replication, a ``secondary`` share replica may be referred
   to as ``passive``, ``non-active`` or simply, ``replica``.


Configuration
~~~~~~~~~~~~~

Two new configuration options have been introduced to support Share
Replication.

replica_state_update_interval
   Specify this option in the ``DEFAULT`` section of your ``manila.conf``.
   The Shared File Systems service requests periodic update of the
   `replica_state` of all ``non-active`` share replicas. The update occurs with
   respect to an interval corresponding to this option. If it is not specified,
   it defaults to 300 seconds.

replication_domain
   Specify this option in the backend stanza when using a multi-backend style
   configuration. The value can be any ASCII string. Two backends that can
   replicate between each other would have the same ``replication_domain``.
   This comes from the premise that the Shared File Systems service expects
   Share Replication to be performed between symmetric backends. This option
   is *required* for using the Share Replication feature.


Health of a share replica
~~~~~~~~~~~~~~~~~~~~~~~~~

Apart from the ``status`` attribute, share replicas have the
``replica_state`` attribute to denote the state of data replication on the
storage backend. The ``primary`` share replica will have it's `replica_state`
attribute set to `active`. The ``secondary`` share replicas may have one of
the following as their ``replica_state``:

in_sync
   The share replica is up to date with the ``active`` share replica (possibly
   within a backend-specific ``recovery point objective``).
out_of_sync
   The share replica is out of date (all new share replicas start out in
   this ``replica_state``).
error
   When the scheduler fails to schedule this share replica or some potentially
   irrecoverable error occurred with regard to updating data for this replica.


Promotion or failover
~~~~~~~~~~~~~~~~~~~~~

For ``readable`` and ``dr`` types of replication, we refer to the task
of switching a `non-active` share replica with the ``active`` replica as
`promotion`. For the ``writable`` style of replication, promotion does
not make sense since all share replicas are ``active`` (or writable) at all
times.

The `status` attribute of the non-active replica being promoted will be
set to ``replication_change`` during its promotion. This has been classified as
a ``busy`` state and thus API interactions with the share are restricted
while one of its share replicas is in this state.


Share replication workflows
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following examples have been implemented with the ZFSonLinux driver that
is a reference implementation in the Shared File Systems service. It operates
in ``driver_handles_share_servers=False`` mode and supports the ``readable``
type of replication. In the example, we assume a configuration of two
Availability Zones [1]_,
called `availability_zone_1` and `availability_zone_2`.

Since the Train release, some drivers operating in
``driver_handles_share_server=True`` mode support share replication.

Multiple availability zones are not necessary to use the replication feature.
However, the use of an availability zone as a ``failure domain`` is encouraged.

Pay attention to the network configuration for the ZFS driver. Here, we assume
a configuration of ``zfs_service_ip`` and ``zfs_share_export_ip`` from two
separate networks. The service network is reachable from the host where the
``manila-share`` service is running. The share export IP is from a network that
allows user access.

See `Configuring the ZFSonLinux driver <https://docs.openstack.org/manila/latest
/configuration/shared-file-systems/drivers/zfs-on-linux-driver.html>`_ for
information on how to set up the ZFSonLinux driver.


Creating a share that supports replication
------------------------------------------

Create a new share type and specify the `replication_type` as an extra-spec
within the share-type being used.


Use the :command:`openstack share type create` command to create a new share type.
Specify the name and the value for the extra-spec
``driver_handles_share_servers``.

.. code-block:: console

   $ openstack share type create readable_type_replication False
   +----------------------+--------------------------------------+
   | Field                | Value                                |
   +----------------------+--------------------------------------+
   | id                   | 3b3ee3f7-6e43-4aa1-859d-0b0511c43074 |
   | name                 | readable_type_replication            |
   | visibility           | public                               |
   | is_default           | -                                    |
   | required_extra_specs | driver_handles_share_servers : False |
   | optional_extra_specs | snapshot_support : True              |
   | description          | None                                 |
   +----------------------+--------------------------------------+

Use the :command:`openstack share type set` command to set an extra-spec to the
share type.

.. code-block:: console

   $ openstack share type set readable_type_replication \
       --extra-specs replication_type=readable

.. note::
   This command has no output. To verify the extra-spec, use the
   :command:`openstack share type list` command and specify the share type's name
   or ID as a parameter.

Create a share with the share type

Use the :command:`openstack share create` command to create a share. Specify the share
protocol, size and the availability zone.

.. code-block:: console

   $ openstack share create NFS 1 --share-type readable_type_replication \
       --name my_share --description "This share will have replicas" \
       --availability-zone availability_zone_1
   +---------------------------------------+--------------------------------------+
   | Field                                 | Value                                |
   +---------------------------------------+--------------------------------------+
   | id                                    | e496ed61-8f2e-436b-b299-32c3e90991cc |
   | size                                  | 1                                    |
   | availability_zone                     | availability_zone_1                  |
   | created_at                            | 2026-03-31T20:22:18.000000           |
   | status                                | creating                             |
   | name                                  | my_share                             |
   | description                           | This share will have replicas        |
   | project_id                            | 48a5ca76ac69405e99dc1c13c5195186     |
   | snapshot_id                           | None                                 |
   | share_network_id                      | None                                 |
   | share_proto                           | NFS                                  |
   | metadata                              | {}                                   |
   | share_type                            | 3b3ee3f7-6e43-4aa1-859d-0b0511c43074 |
   | is_public                             | False                                |
   | snapshot_support                      | True                                 |
   | task_state                            | None                                 |
   | share_type_name                       | readable_type_replication            |
   | access_rules_status                   | active                               |
   | replication_type                      | readable                             |
   | has_replicas                          | False                                |
   | user_id                               | 5c7bdb6eb0504d54a619acf8375c08ce     |
   | create_share_from_snapshot_support    | True                                 |
   | revert_to_snapshot_support            | True                                 |
   | share_group_id                        | None                                 |
   | source_share_group_snapshot_member_id | None                                 |
   | mount_snapshot_support                | True                                 |
   | progress                              | None                                 |
   +---------------------------------------+--------------------------------------+

.. note::
   If you are creating a share with the share type specification
   ``driver_handles_share_servers=True``, the share network parameter is
   required for the operation to be performed.

Use the :command:`openstack share show` command to retrieve details of the share.
Specify the share ID or name as a parameter.

.. code-block:: console

   $ openstack share show my_share
   +---------------------------------------+----------------------------------------------------------------------+
   | Field                                 | Value                                                                |
   +---------------------------------------+----------------------------------------------------------------------+
   | id                                    | e496ed61-8f2e-436b-b299-32c3e90991cc                                 |
   | size                                  | 1                                                                    |
   | availability_zone                     | availability_zone_1                                                  |
   | created_at                            | 2026-03-31T20:22:18.000000                                           |
   | status                                | available                                                            |
   | name                                  | my_share                                                             |
   | description                           | This share will have replicas                                        |
   | project_id                            | 48a5ca76ac69405e99dc1c13c5195186                                     |
   | snapshot_id                           | None                                                                 |
   | share_network_id                      | None                                                                 |
   | share_proto                           | NFS                                                                  |
   | share_type                            | 3b3ee3f7-6e43-4aa1-859d-0b0511c43074                                 |
   | is_public                             | False                                                                |
   | snapshot_support                      | True                                                                 |
   | task_state                            | None                                                                 |
   | share_type_name                       | readable_type_replication                                            |
   | access_rules_status                   | active                                                               |
   | replication_type                      | readable                                                             |
   | has_replicas                          | False                                                                |
   | user_id                               | 5c7bdb6eb0504d54a619acf8375c08ce                                     |
   | create_share_from_snapshot_support    | True                                                                 |
   | revert_to_snapshot_support            | True                                                                 |
   | share_group_id                        | None                                                                 |
   | source_share_group_snapshot_member_id | None                                                                 |
   | mount_snapshot_support                | True                                                                 |
   | progress                              | 100%                                                                 |
   | export_locations                      |                                                                      |
   |                                       | id = e1d754b5-ec06-42d2-afff-3e98c0013faf                            |
   |                                       | path = 192.0.2.26:/alpha/manila_share_38efc042_50c2_4825_a6d8_cba2a  |
   |                                       | preferred = False                                                    |
   | properties                            |                                                                      |
   +---------------------------------------+----------------------------------------------------------------------+


.. note::
   When you create a share that supports replication, an ``active`` replica is
   created for you. You can verify this with the
   :command:`openstack share replica list` command.

   From API version 2.53, when creating a replicated share, the manila quota
   system will reserve and consume resources for two additional quotas:
   ``share_replicas`` and ``replica_gigabytes``.


Creating and promoting share replicas
-------------------------------------

Create a share replica

Use the :command:`openstack share replica create` command to create a share
replica. Specify the share ID or name as a parameter. You may
optionally provide the `availability_zone` or the `scheduler_hints`.

For the scheduler hints, the value of ``only_host`` parameter must be a
manila-share service host in ``host@backend#POOL`` format.

.. code-block:: console

   $ openstack share replica create my_share \
       --availability-zone availability_zone_2 \
       --scheduler-hint only_host=openstack4@zfsonlinux_2#beta
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | id                | 78a5ef96-6c36-42e0-b50b-44efe7c1807e |
   | status            | creating                             |
   | share_id          | e496ed61-8f2e-436b-b299-32c3e90991cc |
   | availability_zone | availability_zone_2                  |
   | created_at        | 2026-03-31T20:24:53.148992           |
   | updated_at        | None                                 |
   | share_network_id  | None                                 |
   | share_server_id   | None                                 |
   | host              |                                      |
   | replica_state     | None                                 |
   +-------------------+--------------------------------------+

See details of the newly created share replica

.. note::
   Since API version 2.51 (Train release), a share network is able to span
   multiple subnets in different availability zones. So, when using a share
   type with specification ``driver_handles_share_servers=True``, users must
   ensure that the share network has a subnet in the availability zone that
   they desire the share replica to be created in.

.. note::
   Scheduler hints are available only for API version >= 2.67.

Use the :command:`openstack share replica show` command to see details
of the newly created share replica. Specify the share replica's ID as a
parameter.

.. code-block:: console

   $ openstack share replica show 78a5ef96-6c36-42e0-b50b-44efe7c1807e
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | id                | 78a5ef96-6c36-42e0-b50b-44efe7c1807e |
   | status            | available                            |
   | share_id          | e496ed61-8f2e-436b-b299-32c3e90991cc |
   | availability_zone | availability_zone_2                  |
   | created_at        | 2026-03-31T20:24:53.000000           |
   | updated_at        | 2026-03-31T20:24:58.000000           |
   | share_network_id  | None                                 |
   | share_server_id   | None                                 |
   | host              | openstack4@zfsonlinux_2#beta         |
   | replica_state     | in_sync                              |
   +-------------------+--------------------------------------+

See all replicas of the share

Use the :command:`openstack share replica list` command to see all the replicas
of the share. Specify the share ID or name as an optional parameter.

.. code-block:: console

   $ openstack share replica list --share-id my_share
   +--------------------------------------+-----------+---------------+--------------------------------------+-------------------------------+---------------------+----------------------------+
   | ID                                   | Status    | Replica State | Share ID                             | Host                          | Availability Zone   | Updated At                 |
   +--------------------------------------+-----------+---------------+--------------------------------------+-------------------------------+---------------------+----------------------------+
   | 38efc042-50c2-4825-a6d8-cba2a8277b28 | available | active        | e496ed61-8f2e-436b-b299-32c3e90991cc | openstack4@zfsonlinux_1#alpha | availability_zone_1 | 2026-03-31T20:22:19.000000 |
   | 78a5ef96-6c36-42e0-b50b-44efe7c1807e | available | in_sync       | e496ed61-8f2e-436b-b299-32c3e90991cc | openstack4@zfsonlinux_2#beta  | availability_zone_2 | 2026-03-31T20:24:58.000000 |
   +--------------------------------------+-----------+---------------+--------------------------------------+-------------------------------+---------------------+----------------------------+

Promote the secondary share replica to be the new active replica

Use the :command:`openstack share replica promote` command to promote a
non-active share replica to become the ``active`` replica. Specify the
non-active replica's ID as a parameter.

.. code-block:: console

   $ openstack share replica promote 78a5ef96-6c36-42e0-b50b-44efe7c1807e

.. note::
   This command has no output.

The promotion may take time. During the promotion, the ``replica_state``
attribute of the share replica being promoted will be set to
``replication_change``.

.. code-block:: console

   $ openstack share replica list --share-id my_share
   +--------------------------------------+-----------+--------------------+--------------------------------------+-------------------------------+---------------------+----------------------------+
   | ID                                   | Status    |    Replica State   | Share ID                             | Host                          | Availability Zone   | Updated At                 |
   +--------------------------------------+-----------+--------------------+--------------------------------------+-------------------------------+---------------------+----------------------------+
   | 38efc042-50c2-4825-a6d8-cba2a8277b28 | available |       active       | e496ed61-8f2e-436b-b299-32c3e90991cc | openstack4@zfsonlinux_1#alpha | availability_zone_1 | 2026-03-31T20:32:19.000000 |
   | 78a5ef96-6c36-42e0-b50b-44efe7c1807e | available | replication_change | e496ed61-8f2e-436b-b299-32c3e90991cc | openstack4@zfsonlinux_2#beta  | availability_zone_2 | 2026-03-31T20:32:19.000000 |
   +--------------------------------------+-----------+--------------------+--------------------------------------+-------------------------------+---------------------+----------------------------+

Once the promotion is complete, the ``replica_state`` will be set to
``active``.

.. code-block:: console

   $ openstack share replica list --share-id my_share
   +--------------------------------------+-----------+---------------+--------------------------------------+-------------------------------+---------------------+----------------------------+
   | ID                                   | Status    | Replica State | Share ID                             | Host                          | Availability Zone   | Updated At                 |
   +--------------------------------------+-----------+---------------+--------------------------------------+-------------------------------+---------------------+----------------------------+
   | 38efc042-50c2-4825-a6d8-cba2a8277b28 | available | in_sync       | e496ed61-8f2e-436b-b299-32c3e90991cc | openstack4@zfsonlinux_1#alpha | availability_zone_1 | 2026-03-31T20:32:19.000000 |
   | 78a5ef96-6c36-42e0-b50b-44efe7c1807e | available | active        | e496ed61-8f2e-436b-b299-32c3e90991cc | openstack4@zfsonlinux_2#beta  | availability_zone_2 | 2026-03-31T20:32:19.000000 |
   +--------------------------------------+-----------+---------------+--------------------------------------+-------------------------------+---------------------+----------------------------+


Access rules
------------

Create an IP access rule for the share

Use the :command:`openstack share access create` command to add an access rule.
Specify the share ID or name, protocol and the target as parameters.

.. code-block:: console

   $ openstack share access create my_share ip 0.0.0.0/0 --access-level rw
   +--------------+--------------------------------------+
   | Field        | Value                                |
   +--------------+--------------------------------------+
   | share_id     | e496ed61-8f2e-436b-b299-32c3e90991cc |
   | access_type  | ip                                   |
   | access_to    | 0.0.0.0/0                            |
   | access_level | rw                                   |
   | state        | new                                  |
   | id           | 8b339cdc-c1e0-448f-bf6d-f068ee6e8f45 |
   +--------------+--------------------------------------+

.. note::
   Access rules are not meant to be different across the replicas of the share.
   However, as per the type of replication, drivers may choose to modify the
   access level prescribed. In the above example, even though read/write access
   was requested for the share, the driver will provide read-only access to
   the non-active replica to the same target, because of the semantics of
   the replication type: ``readable``. However, the target will have read/write
   access to the (currently) non-active replica when it is promoted to
   become the ``active`` replica.

The :command:`openstack share access delete` command can be used to remove a previously
applied access rule.

List the export locations of the share

Use the :command:`openstack share export location list` command to list the
export locations of a share.

.. code-block:: console

   $ openstack share export location list my_share
   +--------------------------------------+-----------------------------------------------------------------------------+-----------+
   | ID                                   | Path                                                                        | Preferred |
   +--------------------------------------+-----------------------------------------------------------------------------+-----------+
   | 3ed3fbf5-2fa1-4dc0-8440-a0af72398cb6 | 192.0.2.21:/beta/subdir/manila_share_78a5ef96_6c36_42e0_b50b_44efe7c1807e   | False     |
   | 6f843ecd-a7ea-4939-86de-e1e01d9e8672 | 203.0.113.23:/alpha/manila_share_38efc042_50c2_4825_a6d8_cba2a8277b28       | False     |
   | e1d754b5-ec06-42d2-afff-3e98c0013faf | 192.0.2.26:/alpha/manila_share_38efc042_50c2_4825_a6d8_cba2a8277b28         | False     |
   | f3c5585f-c2f7-4264-91a7-a4a1e754e686 | 203.0.113.29:/beta/subdir/manila_share_78a5ef96_6c36_42e0_b50b_44efe7c1807e | False     |
   +--------------------------------------+-----------------------------------------------------------------------------+-----------+

Identify the export location corresponding to the share replica on the user
accessible network and you may mount it on the target node.

.. note::
   As an administrator, you can list the export locations for a particular
   share replica by using the
   :command:`openstack share instance export location list` command and
   specifying the share replica's ID as a parameter.


Snapshots
---------

Create a snapshot of the share

Use the :command:`openstack share snapshot create` command to create a snapshot
of the share. Specify the share ID or name as a parameter.

.. code-block:: console

   $ openstack share snapshot create my_share --name "my_snapshot"
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | status            | creating                             |
   | share_id          | e496ed61-8f2e-436b-b299-32c3e90991cc |
   | user_id           | 5c7bdb6eb0504d54a619acf8375c08ce     |
   | description       | None                                 |
   | created_at        | 2026-03-31T21:14:03.000000           |
   | share_proto       | NFS                                  |
   | provider_location | None                                 |
   | id                | 06cdccaf-93a0-4e57-9a39-79fb1929c649 |
   | project_id        | cadd7139bc3148b8973df097c0911016     |
   | size              | 1                                    |
   | share_size        | 1                                    |
   | name              | my_snapshot                          |
   +-------------------+--------------------------------------+


Show the details of the snapshot

Use the :command:`openstack share snapshot show` to view details of a snapshot.
Specify the snapshot ID or name as a parameter.

.. code-block:: console

   $ openstack share snapshot show my_snapshot
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | status            | available                            |
   | share_id          | e496ed61-8f2e-436b-b299-32c3e90991cc |
   | user_id           | 5c7bdb6eb0504d54a619acf8375c08ce     |
   | description       | None                                 |
   | created_at        | 2026-03-31T21:14:03.000000           |
   | share_proto       | NFS                                  |
   | provider_location | None                                 |
   | id                | 06cdccaf-93a0-4e57-9a39-79fb1929c649 |
   | project_id        | cadd7139bc3148b8973df097c0911016     |
   | size              | 1                                    |
   | share_size        | 1                                    |
   | name              | my_snapshot                          |
   +-------------------+--------------------------------------+

.. note::
   The ``status`` attribute of a snapshot will transition from ``creating``
   to ``available`` only when it is present on all the share replicas that have
   their ``replica_state`` attribute set to ``active`` or ``in_sync``.

   Likewise, the ``replica_state`` attribute of a share replica will
   transition from ``out_of_sync`` to ``in_sync`` only when all ``available``
   snapshots are present on it.


Planned failovers
-----------------

As an administrator, you can use the :command:`openstack share replica resync`
command to attempt to sync data between ``active`` and ``non-active`` share
replicas of a share before promotion. This will ensure that share replicas have
the most up-to-date data and their relationships can be safely switched.

.. code-block:: console

   $ openstack share replica resync 38efc042-50c2-4825-a6d8-cba2a8277b28

.. note::
   This command has no output.


Updating attributes
-------------------
If an error occurs while updating data or replication relationships (during
a ``promotion``), the Shared File Systems service may not be able to determine
the consistency or health of a share replica. It may require administrator
intervention to make any fixes on the storage backend as necessary. In such a
situation, state correction within the Shared File Systems service is possible.

As an administrator, you can:

Reset the ``status`` attribute of a share replica

Use the :command:`openstack share replica set` command to reset
the ``status`` attribute. Specify the share replica's ID as a parameter
and use the ``--status`` option to specify the state intended.

.. code-block:: console

   $ openstack share replica set 38efc042-50c2-4825-a6d8-cba2a8277b28 \
       --status=available

.. note::
   This command has no output.


Reset the ``replica_state`` attribute

Use the :command:`openstack share replica set` command to
reset the ``replica_state`` attribute. Specify the share replica's ID
and use the ``--replica-state`` option to specify the state intended.

.. code-block:: console

   $ openstack share replica set 38efc042-50c2-4825-a6d8-cba2a8277b28 \
       --replica-state=out_of_sync

.. note::
   This command has no output.

Force delete a specified share replica in any state

Use the :command:`openstack share replica delete` command with the
'--force' key to remove the share replica, regardless of the state it is in.

.. code-block:: console

   $ openstack share replica show 9513de5d-0384-4528-89fb-957dd9b57680
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | status            | error                                |
   | share_id          | e496ed61-8f2e-436b-b299-32c3e90991cc |
   | availability_zone | availability_zone_1                  |
   | created_at        | 2026-03-31T01:32:47.000000           |
   | updated_at        | 2026-03-31T01:34:25.000000           |
   | share_network_id  | None                                 |
   | share_server_id   | None                                 |
   | host              | openstack4@zfsonlinux_1#alpha        |
   | replica_state     | out_of_sync                          |
   | id                | 38efc042-50c2-4825-a6d8-cba2a8277b28 |
   +-------------------+--------------------------------------+

   $ openstack share replica delete \
       --force 38efc042-50c2-4825-a6d8-cba2a8277b28

.. note::
   This command has no output.

Use the ``policy.yaml`` file to grant permissions for these actions to other
roles.


Deleting share replicas
-----------------------

Use the :command:`openstack share replica delete` command with the share
replica's ID to delete a share replica.

.. code-block:: console

   $ openstack share replica delete 38efc042-50c2-4825-a6d8-cba2a8277b28

.. note::
   This command has no output.

.. note::
   You cannot delete the last ``active`` replica with this command. You should
   use the :command:`openstack share delete` command to remove the share.


.. [1] When running in a multi-backend configuration, until the Stein
       release, deployers could only configure one Availability Zone per manila
       configuration file. This is achieved with the option
       ``storage_availability_zone`` defined under the ``[DEFAULT]`` section.

       Beyond the Stein release, the option ``backend_availability_zone``
       can be specified in each back end stanza. The value of this
       configuration option will override any configuration of the
       ``storage_availability_zone`` from the ``[DEFAULT]`` section.
