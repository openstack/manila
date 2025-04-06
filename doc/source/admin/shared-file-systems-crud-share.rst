.. _shared_file_systems_crud_share:

======================
Share basic operations
======================

General concepts
----------------

To create a file share, and access it, the following general concepts
are prerequisite knowledge:

#. To create a share, use :command:`openstack share create` command and
   specify the required arguments: the size of the share and the shared file
   system protocol. ``NFS``, ``CIFS``, ``GlusterFS``, ``HDFS``, ``CephFS`` or
   ``MAPRFS`` share file system protocols are supported.

#. You can also optionally specify the share network and the share type.

#. After the share becomes available, use the :command:`openstack share show`
   command to get the share export locations.

#. After getting the share export locations, you can create an
   :ref:`access rule <access_to_share>` for the share, mount it and work with
   files on the remote file system.

There are big number of the share drivers created by different vendors in the
Shared File Systems service. As a Python class, each share driver can be set
for the :ref:`back end <shared_file_systems_multi_backend>` and run in the back
end to manage the share operations.

Initially there are two driver modes for the back ends:

* no share servers mode
* share servers mode

Each share driver supports one or two of possible back end modes that can be
configured in the ``manila.conf`` file. The configuration option
``driver_handles_share_servers`` in the ``manila.conf`` file sets the share
servers mode or no share servers mode, and defines the driver mode for share
storage lifecycle management:

+------------------+-------------------------------------+--------------------+
| Mode             | Config option                       |  Description       |
+==================+=====================================+====================+
| no share servers | driver_handles_share_servers = False| An administrator   |
|                  |                                     | rather than a share|
|                  |                                     | driver manages the |
|                  |                                     | bare metal storage |
|                  |                                     | with some net      |
|                  |                                     | interface instead  |
|                  |                                     | of the presence of |
|                  |                                     | the share servers. |
+------------------+-------------------------------------+--------------------+
| share servers    | driver_handles_share_servers = True | The share driver   |
|                  |                                     | creates the share  |
|                  |                                     | server and manages,|
|                  |                                     | or handles, the    |
|                  |                                     | share server life  |
|                  |                                     | cycle.             |
+------------------+-------------------------------------+--------------------+

It is :ref:`the share types <shared_file_systems_share_types>` which have the
extra specifications that help scheduler to filter back ends and choose the
appropriate back end for the user that requested to create a share. The
required extra boolean specification for each share type is
``driver_handles_share_servers``. As an administrator, you can create the share
types with the specifications you need. For details of managing the share types
and configuration the back ends, see :ref:`shared_file_systems_share_types` and
:ref:`shared_file_systems_multi_backend` documentation.

You can create a share in two described above modes:

* in a no share servers mode without specifying the share network and
  specifying the share type with ``driver_handles_share_servers = False``
  parameter. See subsection :ref:`create_share_in_no_share_server_mode`.

* in a share servers mode with specifying the share network and the share
  type with ``driver_handles_share_servers = True`` parameter. See subsection
  :ref:`create_share_in_share_server_mode`.

.. _create_share_in_no_share_server_mode:

Create a share in no share servers mode
---------------------------------------

To create a file share in no share servers mode, you need to:

#. To create a share, use :command:`openstack share create` command and
   specify the required arguments: the size of the share and the shared file
   system protocol. ``NFS``, ``CIFS``, ``GlusterFS``, ``HDFS``, ``CephFS`` or
   ``MAPRFS`` share file system protocols are supported.

#. You should specify the :ref:`share type <shared_file_systems_share_types>`
   with ``driver_handles_share_servers = False`` extra specification.

#. You must not specify the ``share network`` because no share servers are
   created. In this mode the Shared File Systems service expects that
   administrator has some bare metal storage with some net interface.

#. The :command:`openstack share create` command creates a share. This command does the
   following things:

   * The :ref:`manila-scheduler <shared_file_systems_scheduling>` service will
     find the back end with ``driver_handles_share_servers = False`` mode due
     to filtering the extra specifications of the share type.

   * The share is created using the storage that is specified in the found
     back end.

#. After the share becomes available, use the :command:`openstack share show` command
   to get the share export locations.

In the example to create a share, the created already share type named
``dhss_false`` with ``driver_handles_share_servers = False`` extra specification
is used.

Check share types that exist, run:

.. code-block:: console

   $ openstack share type list
   +----------+----------+------------+------------+----------------------+----------------------+-------------+
   | ID       | Name     | Visibility | Is Default | Required Extra Specs | Optional Extra Specs | Description |
   +----------+----------+------------+------------+----------------------+----------------------+-------------+
   | 807e5cd7 | default  | public     | True       | driver_handles_share | snapshot_support :   | None        |
   | -a0e7-   |          |            |            | _servers : True      | True                 |             |
   | 4912-    |          |            |            |                      | create_share_from_sn |             |
   | 8f7d-    |          |            |            |                      | apshot_support :     |             |
   | 352512ce |          |            |            |                      | True                 |             |
   | 51c3     |          |            |            |                      | revert_to_snapshot_s |             |
   |          |          |            |            |                      | upport : True        |             |
   |          |          |            |            |                      | mount_snapshot_suppo |             |
   |          |          |            |            |                      | rt : True            |             |
   | d57dfcb5 | dhss_fal | public     | False      | driver_handles_share | snapshot_support :   | None        |
   | -3026-   | se       |            |            | _servers : False     | True                 |             |
   | 4018-    |          |            |            |                      | create_share_from_sn |             |
   | be87-    |          |            |            |                      | apshot_support :     |             |
   | 3d7ca511 |          |            |            |                      | True                 |             |
   | 60cc     |          |            |            |                      | revert_to_snapshot_s |             |
   |          |          |            |            |                      | upport : True        |             |
   |          |          |            |            |                      | mount_snapshot_suppo |             |
   |          |          |            |            |                      | rt : True            |             |
   | a5e531e6 | dhss_tru | public     | False      | driver_handles_share | snapshot_support :   | None        |
   | -8a89-   | e        |            |            | _servers : True      | True                 |             |
   | 4333-    |          |            |            |                      | create_share_from_sn |             |
   | 9920-    |          |            |            |                      | apshot_support :     |             |
   | 59cd420d |          |            |            |                      | True                 |             |
   | 4f79     |          |            |            |                      | revert_to_snapshot_s |             |
   |          |          |            |            |                      | upport : True        |             |
   |          |          |            |            |                      | mount_snapshot_suppo |             |
   |          |          |            |            |                      | rt : True            |             |
   +----------+----------+------------+------------+----------------------+----------------------+-------------+

Create a private share with ``dhss_false`` share type, NFS shared file system
protocol, and size 1 GB:

.. code-block:: console

   $ openstack share create nfs 1 --name Share1 --description "My share" --share-type dhss_false
   +---------------------------------------+--------------------------------------+
   | Field                                 | Value                                |
   +---------------------------------------+--------------------------------------+
   | id                                    | c1de2cdc-2ccf-4e8d-afe9-b25c84bf3953 |
   | size                                  | 1                                    |
   | availability_zone                     | None                                 |
   | created_at                            | 2025-04-05T22:05:29.343767           |
   | status                                | creating                             |
   | name                                  | Share1                               |
   | description                           | My share                             |
   | project_id                            | c0bc204890ad428796f364b677a8516b     |
   | snapshot_id                           | None                                 |
   | share_network_id                      | None                                 |
   | share_proto                           | NFS                                  |
   | metadata                              | {}                                   |
   | share_type                            | d57dfcb5-3026-4018-be87-3d7ca51160cc |
   | volume_type                           | dhss_false                           |
   | is_public                             | False                                |
   | snapshot_support                      | True                                 |
   | task_state                            | None                                 |
   | share_type_name                       | dhss_false                           |
   | access_rules_status                   | active                               |
   | replication_type                      | None                                 |
   | has_replicas                          | False                                |
   | user_id                               | c5d0c19aae6e4484a41e241f0d8b04fb     |
   | create_share_from_snapshot_support    | True                                 |
   | revert_to_snapshot_support            | True                                 |
   | share_group_id                        | None                                 |
   | source_share_group_snapshot_member_id | None                                 |
   | mount_snapshot_support                | True                                 |
   | progress                              | None                                 |
   | is_soft_deleted                       | False                                |
   | scheduled_to_be_deleted_at            | None                                 |
   | source_backup_id                      | None                                 |
   | share_server_id                       | None                                 |
   | host                                  |                                      |
   +---------------------------------------+--------------------------------------+

New share ``Share1`` should have a status ``available``:

.. code-block:: console

   $ openstack share show Share1
   +---------------------------------------+------------------------------------------+
   | Field                                 | Value                                    |
   +---------------------------------------+------------------------------------------+
   | id                                    | c1de2cdc-2ccf-4e8d-afe9-b25c84bf3953     |
   | size                                  | 1                                        |
   | availability_zone                     | manila-zone-1                            |
   | created_at                            | 2025-04-05T22:05:29.343767               |
   | status                                | available                                |
   | name                                  | Share1                                   |
   | description                           | My share                                 |
   | project_id                            | c0bc204890ad428796f364b677a8516b         |
   | snapshot_id                           | None                                     |
   | share_network_id                      | None                                     |
   | share_proto                           | NFS                                      |
   | share_type                            | d57dfcb5-3026-4018-be87-3d7ca51160cc     |
   | volume_type                           | dhss_false                               |
   | is_public                             | False                                    |
   | snapshot_support                      | True                                     |
   | task_state                            | None                                     |
   | share_type_name                       | dhss_false                               |
   | access_rules_status                   | active                                   |
   | replication_type                      | None                                     |
   | has_replicas                          | False                                    |
   | user_id                               | c5d0c19aae6e4484a41e241f0d8b04fb         |
   | create_share_from_snapshot_support    | True                                     |
   | revert_to_snapshot_support            | True                                     |
   | share_group_id                        | None                                     |
   | source_share_group_snapshot_member_id | None                                     |
   | mount_snapshot_support                | True                                     |
   | progress                              | 100%                                     |
   | is_soft_deleted                       | False                                    |
   | scheduled_to_be_deleted_at            | None                                     |
   | source_backup_id                      | None                                     |
   | share_server_id                       | None                                     |
   | host                                  | manila@paris#shares                      |
   | export_locations                      |                                          |
   |                                       | id =                                     |
   |                                       | 30d8ad5a-05b2-401a-9dbd-caf496f4ab12     |
   |                                       | path = 11.0.0.11:/shares/share_c1de2     |
   |                                       | cdc_2ccf_4e8d_afe9_b25c84bf3953_86ef2    |
   |                                       | fc0_acbe_444c_888a_c52c05242dce          |
   |                                       | preferred = False                        |
   |                                       | metadata = {}                            |
   |                                       | share_instance_id =                      |
   |                                       | 86ef2fc0-acbe-444c-888a-c52c05242dce     |
   |                                       | is_admin_only = True                     |
   |                                       | id =                                     |
   |                                       | acdd47f6-aef5-4d3b-86b2-db7d73d4bbfe     |
   |                                       | path = 10.0.0.10:/shares/share_c1de2     |
   |                                       | cdc_2ccf_4e8d_afe9_b25c84bf3953_86ef2    |
   |                                       | fc0_acbe_444c_888a_c52c05242dce          |
   |                                       | preferred = True                         |
   |                                       | metadata = {}                            |
   |                                       | share_instance_id =                      |
   |                                       | 86ef2fc0-acbe-444c-888a-c52c05242dce     |
   |                                       | is_admin_only = False                    |
   |                                       | id =                                     |
   |                                       | 224f223f-6dea-4e08-92c5-66de161cf43d     |
   |                                       | path = 10.0.0.20:shares/share_c1de2      |
   |                                       | cdc_2ccf_4e8d_afe9_b25c84bf3953_86ef2    |
   |                                       | fc0_acbe_444c_888a_c52c05242dce          |
   |                                       | preferred = False                        |
   |                                       | metadata = {}                            |
   |                                       | share_instance_id =                      |
   |                                       | 86ef2fc0-acbe-444c-888a-c52c05242dce     |
   |                                       | is_admin_only = False                    |
   | properties                            |                                          |
   +---------------------------------------+------------------------------------------+

.. _create_share_in_share_server_mode:

Create a share in share servers mode
------------------------------------

To create a file share in share servers mode, you need to:

#. To create a share, use :command:`openstack share create` command and
   specify the required arguments: the size of the share and the shared file
   system protocol. ``NFS``, ``CIFS``, ``GlusterFS``, ``HDFS``, ``CephFS`` or
   ``MAPRFS`` share file system protocols are supported.

#. You should specify the :ref:`share type <shared_file_systems_share_types>`
   with ``driver_handles_share_servers = True`` extra specification.

#. You should specify the
   :ref:`share network <shared_file_systems_share_networks>`.

#. The :command:`openstack share create` command creates a share. This command does the
   following things:

   * The :ref:`manila-scheduler <shared_file_systems_scheduling>` service will
     find the back end with ``driver_handles_share_servers = True`` mode due to
     filtering the extra specifications of the share type.

   * The share driver will create a share server with the share network. For
     details of creating the resources, see the `documentation <http://docs.openstack.
     org/manila/latest/admin/shared-file-systems-multi-backend.html>`_ of the specific
     share driver.

#. After the share becomes available, use the :command:`manila show` command
   to get the share export location.

In the example to create a share, the default share type and the already
existing share network are used.

.. note::

   There is no default share type just after you started manila as the
   administrator. See :ref:`shared_file_systems_share_types` to
   create the default share type. To create a share network, use
   :ref:`shared_file_systems_share_networks`.

Check share networks that exist, run:

.. code-block:: console

   $ openstack share network list
   +--------------------------------------+-------+
   | ID                                   | Name  |
   +--------------------------------------+-------+
   | 1e0b9a80-2bce-4244-9da4-f8589c6bd56b | mynet |
   +--------------------------------------+-------+

Create a public share with ``my_share_net`` network, ``default``
share type, NFS shared file system protocol, and size 1 GB:

.. code-block:: console

   $ openstack share create nfs 1 \
       --name "Share2" \
       --description "My second share" \
       --share-type default \
       --share-network my_net \
       --metadata aim=testing \
       --public
   +---------------------------------------+--------------------------------------+
   | Property                              | Value                                |
   +---------------------------------------+--------------------------------------+
   | id                                    | a37c3d1d-023f-4fcf-b640-3dbbb3e89193 |
   | size                                  | 1                                    |
   | availability_zone                     | None                                 |
   | created_at                            | 2025-04-05T22:25:51.609837           |
   | status                                | creating                             |
   | name                                  | Share2                               |
   | description                           | My second share                      |
   | project_id                            | c0bc204890ad428796f364b677a8516b     |
   | snapshot_id                           | None                                 |
   | share_network_id                      | 1e0b9a80-2bce-4244-9da4-f8589c6bd56b |
   | share_proto                           | NFS                                  |
   | metadata                              | {'aim': 'testing'}                   |
   | share_type                            | 807e5cd7-a0e7-4912-8f7d-352512ce51c3 |
   | is_public                             | True                                 |
   | snapshot_support                      | True                                 |
   | task_state                            | None                                 |
   | share_type_name                       | default                              |
   | access_rules_status                   | active                               |
   | replication_type                      | None                                 |
   | has_replicas                          | False                                |
   | user_id                               | c5d0c19aae6e4484a41e241f0d8b04fb     |
   | create_share_from_snapshot_support    | True                                 |
   | revert_to_snapshot_support            | True                                 |
   | share_group_id                        | None                                 |
   | source_share_group_snapshot_member_id | None                                 |
   | mount_snapshot_support                | True                                 |
   | progress                              | None                                 |
   | is_soft_deleted                       | False                                |
   | scheduled_to_be_deleted_at            | None                                 |
   | source_backup_id                      | None                                 |
   | share_server_id                       | None                                 |
   | host                                  |                                      |
   +---------------------------------------+--------------------------------------+

The share also can be created from a share snapshot. For details, see
:ref:`shared_file_systems_snapshots`.

See the share in a share list:

.. code-block:: console

   $ openstack share list
   +--------------------------------------+----------------+------+-------------+--------------+-----------+-----------------+----------------------+-------------------+
   | ID                                   | Name           | Size | Share Proto | Status       | Is Public | Share Type Name | Host                 | Availability Zone |
   +--------------------------------------+----------------+------+-------------+--------------+-----------+-----------------+----------------------+-------------------+
   | a37c3d1d-023f-4fcf-b640-3dbbb3e89193 | Share2         | 1    | NFS         | available    | True      | default         | manila@lima#shares   | manila-zone-1     |
   | c1de2cdc-2ccf-4e8d-afe9-b25c84bf3953 | Share1         | 1    | NFS         | available    | False     | dhss_false      | manila@paris#shares  | manila-zone-1     |
   +--------------------------------------+----------------+------+-------------+--------------+-----------+-----------------+----------------------+-------------------+

Check the share status and see the share export locations. After ``creating``
status share should have status ``available``:

.. code-block:: console

   $ openstack share show Share2
   +---------------------------------------+------------------------------------------+
   | Field                                 | Value                                    |
   +---------------------------------------+------------------------------------------+
   | id                                    | a37c3d1d-023f-4fcf-b640-3dbbb3e89193     |
   | size                                  | 1                                        |
   | availability_zone                     | manila-zone-1                            |
   | created_at                            | 2025-04-05T22:25:51.609837               |
   | status                                | available                                |
   | name                                  | Share2                                   |
   | description                           | My second share                          |
   | project_id                            | c0bc204890ad428796f364b677a8516b         |
   | snapshot_id                           | None                                     |
   | share_network_id                      | 1e0b9a80-2bce-4244-9da4-f8589c6bd56b     |
   | share_proto                           | NFS                                      |
   | share_type                            | 807e5cd7-a0e7-4912-8f7d-352512ce51c3     |
   | volume_type                           | default                                  |
   | is_public                             | True                                     |
   | snapshot_support                      | True                                     |
   | task_state                            | None                                     |
   | share_type_name                       | default                                  |
   | access_rules_status                   | active                                   |
   | replication_type                      | None                                     |
   | has_replicas                          | False                                    |
   | user_id                               | c5d0c19aae6e4484a41e241f0d8b04fb         |
   | create_share_from_snapshot_support    | True                                     |
   | revert_to_snapshot_support            | True                                     |
   | share_group_id                        | None                                     |
   | source_share_group_snapshot_member_id | None                                     |
   | mount_snapshot_support                | True                                     |
   | progress                              | None                                     |
   | is_soft_deleted                       | False                                    |
   | scheduled_to_be_deleted_at            | None                                     |
   | source_backup_id                      | None                                     |
   | share_server_id                       | None                                     |
   | host                                  | manila@lima#shares                       |
   | export_locations                      |                                          |
   |                                       | id =                                     |
   |                                       | aeac5f3e-60e3-461c-8ca8-6696e0f59f39     |
   |                                       | path = 12.0.0.12:/shares/share_cdc_2c    |
   |                                       | cf_4e8d_afe9_b25c84bf3953_86ef2          |
   |                                       | 789-f1f5-4171-9e43-3afabddf8b5f          |
   |                                       | preferred = False                        |
   |                                       | metadata = {}                            |
   |                                       | share_instance_id =                      |
   |                                       | 86ef2fc0-acbe-444c-888a-c52c05242dce     |
   |                                       | is_admin_only = True                     |
   |                                       | id =                                     |
   |                                       | 965aa536-9ba4-4f8b-9ddd-a6a916968597     |
   |                                       | path = 10.0.0.10:/shares/share_cdc_2c    |
   |                                       | cf_4e8d_afe9_b25c84bf3953_86ef2          |
   |                                       | 789-f1f5-4171-9e43-3afabddf8b5f          |
   |                                       | preferred = True                         |
   |                                       | metadata = {}                            |
   |                                       | share_instance_id =                      |
   |                                       | 86ef2fc0-acbe-444c-888a-c52c05242dce     |
   |                                       | is_admin_only = False                    |
   |                                       | id =                                     |
   |                                       | 224f223f-6dea-4e08-92c5-66de161cf43d     |
   |                                       | path = 10.0.0.20:/shares/share_cdc_2c    |
   |                                       | cf_4e8d_afe9_b25c84bf3953_86ef2          |
   |                                       | 789-f1f5-4171-9e43-3afabddf8b5f          |
   |                                       | preferred = False                        |
   |                                       | metadata = {}                            |
   |                                       | share_instance_id =                      |
   |                                       | 86ef2fc0-acbe-444c-888a-c52c05242dce     |
   | properties                            | aim='testing'                            |
   +---------------------------------------+------------------------------------------+

``is_public`` defines the level of visibility for the share: whether other
projects can or cannot see the share. By default, the share is private.

Update share
------------

Update the name, or description, or level of visibility for all projects for
the share if you need:

.. code-block:: console

   $ openstack share set Share2 --description "My second share. Updated" --public False

   $ openstack share show Share2
   +---------------------------------------+--------------------------------------+
   | Field                                 | Value                                |
   +---------------------------------------+--------------------------------------+
   | id                                    | a37c3d1d-023f-4fcf-b640-3dbbb3e89193 |
   | size                                  | 1                                    |
   | availability_zone                     | manila-zone-1                        |
   | created_at                            | 2025-04-05T22:25:51.609837           |
   | status                                | available                            |
   | name                                  | Share2                               |
   | description                           | My second share. Updated             |
   | project_id                            | c0bc204890ad428796f364b677a8516b     |
   | snapshot_id                           | None                                 |
   | share_network_id                      | 1e0b9a80-2bce-4244-9da4-f8589c6bd56b |
   | share_proto                           | NFS                                  |
   | share_type                            | 807e5cd7-a0e7-4912-8f7d-352512ce51c3 |
   | volume_type                           | default                              |
   | is_public                             | False                                |
   | snapshot_support                      | True                                 |
   | task_state                            | None                                 |
   | share_type_name                       | default                              |
   | access_rules_status                   | active                               |
   | replication_type                      | None                                 |
   | has_replicas                          | False                                |
   | user_id                               | c5d0c19aae6e4484a41e241f0d8b04fb     |
   | create_share_from_snapshot_support    | True                                 |
   | revert_to_snapshot_support            | True                                 |
   | share_group_id                        | None                                 |
   | source_share_group_snapshot_member_id | None                                 |
   | mount_snapshot_support                | True                                 |
   | progress                              | None                                 |
   | is_soft_deleted                       | False                                |
   | scheduled_to_be_deleted_at            | None                                 |
   | source_backup_id                      | None                                 |
   | share_server_id                       | None                                 |
   | host                                  | manila@lima#shares                   |
   | export_locations                      |                                      |
   | properties                            | aim='testing'                        |
   +---------------------------------------+--------------------------------------+

A share can have one of these status values:

+-----------------------------------+-----------------------------------------+
| Status                            | Description                             |
+===================================+=========================================+
| creating                          | The share is being created.             |
+-----------------------------------+-----------------------------------------+
| deleting                          | The share is being deleted.             |
+-----------------------------------+-----------------------------------------+
| error                             | An error occurred during share creation.|
+-----------------------------------+-----------------------------------------+
| error_deleting                    | An error occurred during share deletion.|
+-----------------------------------+-----------------------------------------+
| available                         | The share is ready to use.              |
+-----------------------------------+-----------------------------------------+
| manage_starting                   | Share manage started.                   |
+-----------------------------------+-----------------------------------------+
| manage_error                      | Share manage failed.                    |
+-----------------------------------+-----------------------------------------+
| unmanage_starting                 | Share unmanage started.                 |
+-----------------------------------+-----------------------------------------+
| unmanage_error                    | Share cannot be unmanaged.              |
+-----------------------------------+-----------------------------------------+
| unmanaged                         | Share was unmanaged.                    |
+-----------------------------------+-----------------------------------------+
| extending                         | The extend, or increase, share size     |
|                                   | request was issued successfully.        |
+-----------------------------------+-----------------------------------------+
| extending_error                   | Extend share failed.                    |
+-----------------------------------+-----------------------------------------+
| shrinking                         | Share is being shrunk.                  |
+-----------------------------------+-----------------------------------------+
| shrinking_error                   | Failed to update quota on share         |
|                                   | shrinking.                              |
+-----------------------------------+-----------------------------------------+
| shrinking_possible_data_loss_error| Shrink share failed due to possible data|
|                                   | loss.                                   |
+-----------------------------------+-----------------------------------------+
| migrating                         | Share migration is in progress.         |
+-----------------------------------+-----------------------------------------+

.. _share_metadata:

Share metadata
--------------

If you want to set the metadata key-value pairs on the share, run:

.. code-block:: console

   $  openstack share set Share2 --property project=my_abc

Get all metadata key-value pairs of the share:

.. code-block:: console

   $ openstack share show -c properties Share2
   +------------+------------------------------------------------------+
   | Field      | Value                                                |
   +------------+------------------------------------------------------+
   | properties | aim='testing', deadline='01/20/16', project='my_abc' |
   +------------+------------------------------------------------------+

You can update the metadata:

.. code-block:: console

   $ openstack share set Share2 --proper deadline='01/30/16'
   $ openstack share show -c properties Share2
   +------------+------------------------------------------------------+
   | Field      | Value                                                |
   +------------+------------------------------------------------------+
   | properties | aim='testing', deadline='01/30/16', project='my_abc' |
   +------------+------------------------------------------------------+

You also can unset the metadata using
**openstack share unset <share_name> --property <key_to_unset>**.

.. note::
  In case you want to prevent certain metadata key-values to be manipulated by
  less privileged users, you can provide a list of such keys through the admin
  only metadata configuration option listed in the
  :ref:`additional configuration options page <manila-common>`.

  In case you want to pass certain metadata key-values to be consumed by share
  drivers, you can provide a list of such keys through the driver updatable
  metadata configuration option listed in the
  :ref:`additional configuration options page <manila-common>`.

Reset share state
-----------------

As administrator, you can reset the state of a share.

Use **openstack share set <share> --status** command to reset share
state, where ``state`` indicates which state to assign the share. Options
include ``available``, ``error``, ``creating``, ``deleting``,
``error_deleting`` states.

.. code-block:: console

   $ openstack share set Share2 --status deleting

   $ openstack share show Share2
   +---------------------------------------+--------------------------------------+
   | Field                                 | Value                                |
   +---------------------------------------+--------------------------------------+
   | id                                    | a37c3d1d-023f-4fcf-b640-3dbbb3e89193 |
   | size                                  | 1                                    |
   | availability_zone                     | manila-zone-1                        |
   | created_at                            | 2025-04-05T22:25:51.609837           |
   | status                                | deleting                             |
   | name                                  | Share2                               |
   | description                           | My second share. Updated             |
   | project_id                            | c0bc204890ad428796f364b677a8516b     |
   | snapshot_id                           | None                                 |
   | share_network_id                      | 1e0b9a80-2bce-4244-9da4-f8589c6bd56b |
   | share_proto                           | NFS                                  |
   | share_type                            | 807e5cd7-a0e7-4912-8f7d-352512ce51c3 |
   | volume_type                           | default                              |
   | is_public                             | False                                |
   | snapshot_support                      | True                                 |
   | task_state                            | None                                 |
   | share_type_name                       | default                              |
   | access_rules_status                   | active                               |
   | replication_type                      | None                                 |
   | has_replicas                          | False                                |
   | user_id                               | c5d0c19aae6e4484a41e241f0d8b04fb     |
   | create_share_from_snapshot_support    | True                                 |
   | revert_to_snapshot_support            | True                                 |
   | share_group_id                        | None                                 |
   | source_share_group_snapshot_member_id | None                                 |
   | mount_snapshot_support                | True                                 |
   | progress                              | None                                 |
   | is_soft_deleted                       | False                                |
   | scheduled_to_be_deleted_at            | None                                 |
   | source_backup_id                      | None                                 |
   | share_server_id                       | None                                 |
   | host                                  | manila@lima#shares                   |
   | export_locations                      |                                      |
   | properties                            | deadline='01/30/16'                  |
   +---------------------------------------+--------------------------------------+

Delete and force-delete share
-----------------------------

You also can force-delete a share.
The shares cannot be deleted in transitional states. The transitional
states are ``creating``, ``deleting``, ``managing``, ``unmanaging``,
``migrating``, ``extending``, and ``shrinking`` statuses for the shares.
Force-deletion deletes an object in any state. Use the ``policy.yaml`` file
to grant permissions for this action to other roles.

.. tip::

   The configuration file ``policy.yaml`` may be used from different places.
   The path ``/etc/manila/policy.yaml`` is one of expected paths by default.

Use **openstack share delete <share_name_or_ID>** command to delete a specified share:

.. code-block:: console

   $ openstack share delete %share_name_or_id%

.. code-block:: console

   $ openstack share delete %share_name_or_id% --share-group %share-group-id%

.. code-block:: console

   $ openstack share delete Share2

Print the list of all shares for all projects:

.. code-block:: console

   $ openstack share delete --force Share2

   $ openstack share list --all
   +--------------------------------------+----------------+------+-------------+--------------+-----------+-----------------+------------------------+-------------------+
   | ID                                   | Name           | Size | Share Proto | Status       | Is Public | Share Type Name | Host                   | Availability Zone |
   +--------------------------------------+----------------+------+-------------+--------------+-----------+-----------------+------------------------+-------------------+
   | c1de2cdc-2ccf-4e8d-afe9-b25c84bf3953 | Share1         | 1    | NFS         | available    | False     | default         | manila@paris#shares    | manila-zone-1     |
   +--------------------------------------+----------------+------+-------------+--------------+-----------+-----------------+------------------------+-------------------+

.. _access_to_share:

Manage access to share
----------------------

The Shared File Systems service allows to grant or deny access to a specified
share, and list the permissions for a specified share.

To grant or deny access to a share, specify one of these supported share
access levels:

- **rw**. Read and write (RW) access. This is the default value.

- **ro**. Read-only (RO) access.

You must also specify one of these supported authentication methods:

- **ip**. Authenticates an instance through its IP address. A valid
  format is ``XX.XX.XX.XX`` or ``XX.XX.XX.XX/XX``. For example ``0.0.0.0/0``.

- **user**. Authenticates by a specified user or group name. A valid value is
  an alphanumeric string that can contain some special characters and is from
  4 to 32 characters long.

- **cert**. Authenticates an instance through a TLS certificate. Specify the
  TLS identity as the IDENTKEY. A valid value is any string up to 64 characters
  long in the common name (CN) of the certificate. The meaning of a string
  depends on its interpretation.

- **cephx**. Ceph authentication system. Specify the Ceph auth ID that needs
  to be authenticated and authorized for share access by the Ceph back end. A
  valid value must be non-empty, consist of ASCII printable characters, and not
  contain periods.

Try to mount NFS share with export path
``10.0.0.10:/shares/share_cdc_2ccf_4e8d_afe9_b25c84bf3953_86ef2789-f1f5-4171-9e43-3afabddf8b5f`` on the
node with IP address ``10.0.0.13``:

.. code-block:: console

   $ sudo mount -v -t nfs 10.0.0.10:/shares/share_cdc_2ccf_4e8d_afe9_b25c84bf3953_86ef2789-f1f5-4171-9e43-3afabddf8b5f /mnt/
   mount.nfs: timeout set for Tue Oct  6 10:37:23 2015
   mount.nfs: trying text-based options 'vers=4,addr=10.0.0.10,clientaddr=10.0.0.13'
   mount.nfs: mount(2): Permission denied
   mount.nfs: access denied by server while mounting 10.0.0.10:/shares/share_cdc_2ccf_4e8d_afe9_b25c84bf3953_86ef2789-f1f5-4171-9e43-3afabddf8b5f

An error message "Permission denied" appeared, so you are not allowed to mount
a share without an access rule. Allow access to the share with ``ip`` access
type and ``10.0.2.13`` IP address:

.. code-block:: console

   $ openstack share access create Share1 ip 10.0.2.13 --access-level rw
   +--------------+--------------------------------------+
   | Field        | Value                                |
   +--------------+--------------------------------------+
   | id           | 56d344c5-95cb-477b-bf33-39f6e9b43edf |
   | share_id     | c1de2cdc-2ccf-4e8d-afe9-b25c84bf3953 |
   | access_level | rw                                   |
   | access_to    | 10.0.2.13                            |
   | access_type  | ip                                   |
   | state        | queued_to_apply                      |
   | access_key   | None                                 |
   | created_at   | 2025-04-05T23:44:31.165395           |
   | updated_at   | None                                 |
   | properties   |                                      |
   +--------------+--------------------------------------+

Try to mount a share again. This time it is mounted successfully:

.. code-block:: console

   $ sudo mount -v -t nfs 10.0.0.10:/shares/share_cdc_2ccf_4e8d_afe9_b25c84bf3953_86ef2789-f1f5-4171-9e43-3afabddf8b5f /mnt/

.. note::

   Different share features are supported by different share drivers.
   For the example, the Generic driver with the Block Storage service as a
   back-end doesn't support ``user`` and ``cert`` authentications methods. For
   details of supporting of features by different drivers, see `Manila share
   features support mapping <https://docs.openstack.org/manila/latest/admin
   /share_back_ends_feature_support_mapping.html>`_.

.. tip::

  Starting from the 2023.2 (Bobcat) release, in case you want to restrict the
  visibility of the sensitive fields (``access_to`` and ``access_key``), or
  avoid the access rule being deleted by other users, you can specify
  ``--lock-visibility`` and ``--lock-deletion`` in the Manila OpenStack command
  for creating access rules. A reason (``--lock-reason``) can also be provided.
  Only the user that placed the lock, system administrators and services will
  be able to view sensitive fields of, or manipulate such access rules by
  virtue of default RBAC. In case the deletion of the access rule was locked,
  Manila will also place an additional lock on the share, to ensure it will
  not be deleted and cause disconnections.

To verify that the access rules (ACL) were configured correctly for a share,
you list permissions for a share:

.. code-block:: console

   $ openstack share access list Share1
   +--------------------------------------+-------------+-----------+--------------+--------+------------+----------------------------+-------------------------+
   | ID                                   | Access Type | Access To | Access Level | State  | Access Key | Created At                 | Updated At              |
   +--------------------------------------+-------------+-----------+--------------+--------+------------+----------------------------+-------------------------+
   | 56d344c5-95cb-477b-bf33-39f6e9b43edf | ip          | 10.0.0.13 | rw           | active | None       | 2025-04-05T23:44:31.165395 | 2025-04-05T23:45:50.780 |
   +--------------------------------------+-------------+-----------+--------------+--------+------------+----------------------------+-------------------------+

Deny access to the share and check that deleted access rule is absent in the
access rule list:

.. code-block:: console

   $ openstack share access delete Share1 56d344c5-95cb-477b-bf33-39f6e9b43edf

.. note::

  Starting from the 2023.2 (Bobcat) release, it is possible to prevent the
  deletion of an access rule. In case the deletion was locked, the
  ``--unrestrict`` argument from the Manila's OpenStack Client must be used
  in the request to revoke the access.
