.. -*- rst -*-

Shares
======

A share is a remote, mountable file system. In the APIs below, a share
resource is a representation of this remote file system within the Shared
File Systems service. This resource representation includes useful metadata,
communicating the characteristics of the remote file system as determined by
the user and the Shared File Systems service.

You can create a share and associate it with a network, list
shares, and show information for, update, and delete a share.

To create a share, specify one of these supported protocols:

- ``NFS``. Network File System (NFS).

- ``CIFS``. Common Internet File System (CIFS).

- ``GLUSTERFS``. Gluster file system (GlusterFS).

- ``HDFS``. Hadoop Distributed File System (HDFS).

- ``CEPHFS``. Ceph File System (CephFS).

- ``MAPRFS``. MapR File System (MAPRFS).

You can also create snapshots of shares. To create a snapshot, you
specify the ID of the share that you want to snapshot.

A share has one of these status values:

**Share statuses**

+----------------------------------------+--------------------------------------------------------+
| Status                                 | Description                                            |
+----------------------------------------+--------------------------------------------------------+
| ``backup_creating``                    | The share is being backed up.                          |
+----------------------------------------+--------------------------------------------------------+
| ``backup_restoring``                   | The share is being restored from backup.               |
+----------------------------------------+--------------------------------------------------------+
| ``backup_restoring_error``             | An error occurred during share backup restore.         |
+----------------------------------------+--------------------------------------------------------+
| ``creating``                           | The share is being created.                            |
+----------------------------------------+--------------------------------------------------------+
| ``creating_from_snapshot``             | The share is being created from a parent snapshot.     |
+----------------------------------------+--------------------------------------------------------+
| ``deleting``                           | The share is being deleted.                            |
+----------------------------------------+--------------------------------------------------------+
| ``deleted``                            | The share was deleted.                                 |
+----------------------------------------+--------------------------------------------------------+
| ``error``                              | An error occurred during share creation.               |
+----------------------------------------+--------------------------------------------------------+
| ``error_deleting``                     | An error occurred during share deletion.               |
+----------------------------------------+--------------------------------------------------------+
| ``available``                          | The share is ready to use.                             |
+----------------------------------------+--------------------------------------------------------+
| ``inactive``                           | The share is inactive.                                 |
+----------------------------------------+--------------------------------------------------------+
| ``manage_starting``                    | Share manage started.                                  |
+----------------------------------------+--------------------------------------------------------+
| ``manage_error``                       | Share manage failed.                                   |
+----------------------------------------+--------------------------------------------------------+
| ``unmanage_starting``                  | Share unmanage started.                                |
+----------------------------------------+--------------------------------------------------------+
| ``unmanage_error``                     | Share cannot be unmanaged.                             |
+----------------------------------------+--------------------------------------------------------+
| ``unmanaged``                          | Share was unmanaged.                                   |
+----------------------------------------+--------------------------------------------------------+
| ``extending``                          | The extend, or increase, share size request was issued |
|                                        | successfully.                                          |
+----------------------------------------+--------------------------------------------------------+
| ``extending_error``                    | Extend share failed.                                   |
+----------------------------------------+--------------------------------------------------------+
| ``shrinking``                          | Share is being shrunk.                                 |
+----------------------------------------+--------------------------------------------------------+
| ``shrinking_error``                    | Failed to update quota on share shrinking.             |
+----------------------------------------+--------------------------------------------------------+
| ``shrinking_possible_data_loss_error`` | Shrink share failed due to possible data loss.         |
+----------------------------------------+--------------------------------------------------------+
| ``migrating``                          | Share is currently migrating.                          |
+----------------------------------------+--------------------------------------------------------+
| ``migrating_to``                       | Share is a migration destination.                      |
+----------------------------------------+--------------------------------------------------------+
| ``replication_change``                 | The share is undergoing a replication change.          |
+----------------------------------------+--------------------------------------------------------+
| ``reverting``                          | Share is being reverted to a snapshot.                 |
+----------------------------------------+--------------------------------------------------------+
| ``reverting_error``                    | Share revert to snapshot failed.                       |
+----------------------------------------+--------------------------------------------------------+
| ``awaiting_transfer``                  | Share is being transferred to a different project's    |
|                                        | namespace.                                             |
+----------------------------------------+--------------------------------------------------------+


List shares
~~~~~~~~~~~

.. rest_method::  GET /v2/shares

Lists all shares.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - all_tenants: all_tenants_query
   - name: name_query
   - status: status_query
   - share_server_id: share_server_id_query
   - metadata: metadata_query
   - extra_specs: extra_specs_query
   - share_type_id: share_type_id_query
   - snapshot_id: snapshot_id_query
   - source_backup_id: source_backup_id_query
   - host: host_query
   - share_network_id: share_network_id_query
   - project_id: project_id_query
   - is_public: is_public_query
   - share_group_id: share_group_id_query
   - export_location_id: export_location_id_query
   - export_location_path: export_location_path_query
   - name~: name_inexact_query
   - description~: description_inexact_query
   - with_count: with_count_query
   - is_soft_deleted: is_soft_deleted_query
   - limit: limit
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_id_response
   - links: links
   - name: name
   - count: count

Response example
----------------

.. literalinclude:: samples/shares-list-response.json
   :language: javascript


List shares with details
~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/shares/detail

Lists all shares, with details.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - all_tenants: all_tenants_query
   - status: status_query
   - share_server_id: share_server_id_query
   - metadata: metadata_query
   - extra_specs: extra_specs_query
   - share_type_id: share_type_id_query
   - name: name_query
   - snapshot_id: snapshot_id_query
   - source_backup_id: source_backup_id_query
   - host: host_query
   - share_network_id: share_network_id_query
   - project_id: project_id_query
   - is_public: is_public_query
   - share_group_id: share_group_id_query
   - export_location_id: export_location_id_query
   - export_location_path: export_location_path_query
   - name~: name_inexact_query
   - description~: description_inexact_query
   - with_count: with_count_query
   - is_soft_deleted: is_soft_deleted_query
   - limit: limit
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_id_response
   - size: size_response
   - availability_zone: availability_zone
   - created_at: created_at
   - status: share_status_response
   - name: name
   - description: description
   - project_id: project_id
   - snapshot_id: snapshot_id_shares_response
   - source_backup_id: source_backup_id_shares_response
   - share_network_id: share_network_id
   - share_proto: share_proto
   - metadata: metadata
   - share_type: share_type_shares_response
   - links: links
   - is_public: is_public_shares_response
   - share_server_id: share_server_id
   - host: host_resource_response
   - snapshot_support: snapshot_support_share_capability
   - task_state: task_state
   - share_type_name: share_type_name
   - access_rules_status: access_rules_status
   - replication_type: replication_type_share_capability
   - has_replicas: has_replicas
   - user_id: share_user_id
   - create_share_from_snapshot_support: create_share_from_snapshot_support_share_capability
   - revert_to_snapshot_support: revert_to_snapshot_support_share_capability
   - share_group_id: share_group_id
   - source_share_group_snapshot_member_id: source_share_group_snapshot_member_id
   - mount_snapshot_support: mount_snapshot_support_share_capability
   - progress: progress_share_instance
   - count: count
   - volume_type: volume_type_shares_response
   - export_location: export_location
   - export_locations: export_locations
   - is_soft_deleted: is_soft_deleted_response
   - scheduled_to_be_deleted_at: scheduled_to_be_deleted_at_response


Response example
----------------

.. literalinclude:: samples/shares-list-detailed-response.json
   :language: javascript


Show share details
~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/shares/{share_id}

Shows details for a share.


Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_id_response
   - size: size_response
   - availability_zone: availability_zone
   - created_at: created_at
   - status: share_status_response
   - name: name
   - description: description
   - project_id: project_id
   - snapshot_id: snapshot_id_shares_response
   - share_network_id: share_network_id
   - share_proto: share_proto
   - metadata: metadata
   - share_type: share_type_shares_response
   - links: links
   - is_public: is_public_shares_response
   - share_server_id: share_server_id
   - host: host_resource_response
   - snapshot_support: snapshot_support_share_capability
   - task_state: task_state
   - share_type_name: share_type_name
   - access_rules_status: access_rules_status
   - replication_type: replication_type_share_capability
   - has_replicas: has_replicas
   - user_id: share_user_id
   - create_share_from_snapshot_support: create_share_from_snapshot_support_share_capability
   - revert_to_snapshot_support: revert_to_snapshot_support_share_capability
   - share_group_id: share_group_id
   - source_share_group_snapshot_member_id: source_share_group_snapshot_member_id
   - mount_snapshot_support: mount_snapshot_support_share_capability
   - progress: progress_share_instance
   - count: count
   - volume_type: volume_type_shares_response
   - export_location: export_location
   - export_locations: export_locations
   - is_soft_deleted: is_soft_deleted_response
   - scheduled_to_be_deleted_at: scheduled_to_be_deleted_at_response

Response example
----------------

.. literalinclude:: samples/share-show-response.json
   :language: javascript


List share instances
~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/shares/{share_id}/instances

.. versionadded:: 2.3

Lists instances of a share.

A share instance is an internal representation for a share. A share that is
replicated or is in the process of being migrated is physically stored in
multiple locations. Each of these individual locations is called an "instance"
within the Shared File Systems service. End users need not be concerned with
this internal representation. As an administrator, you can list all instances
of a share through this endpoint resource. Use the ``policy.yaml`` file to
grant permissions for this action to other roles.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: share_status_response
   - access_rules_status: access_rules_status
   - share_id: share_id_share_instances_response
   - progress: progress_share_instance
   - availability_zone: availability_zone
   - created_at: created_at
   - replica_state: replica_state
   - export_location: export_location
   - export_locations: export_locations
   - cast_rules_to_readonly: share_instance_cast_rules_to_readonly
   - share_network_id: share_network_id
   - share_server_id: share_server_id
   - host: host_resource_response
   - access_rules_status: access_rules_status
   - share_type_id: share_type_id
   - id: id_13

Response example
----------------

.. literalinclude:: samples/share-instances-list-response.json
   :language: javascript

Create share
~~~~~~~~~~~~

.. rest_method::  POST /v2/shares

Creates a share.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409
   - 422

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_proto: share_proto
   - size: size_request
   - name: name_request
   - description: description_request
   - display_name: display_name_request
   - display_description: display_description_request
   - share_type: share_type_request
   - snapshot_id: snapshot_id_request
   - is_public: is_public_request
   - share_group_id: share_group_id_request
   - metadata: metadata
   - share_network_id: share_network_id_request
   - availability_zone: availability_zone_request
   - scheduler_hints: scheduler_hints

Request example
---------------

.. literalinclude:: samples/share-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_id_response
   - size: size_response
   - availability_zone: availability_zone
   - created_at: created_at
   - status: share_status_response
   - name: name
   - description: description
   - project_id: project_id
   - snapshot_id: snapshot_id_shares_response
   - share_network_id: share_network_id
   - share_proto: share_proto
   - metadata: metadata
   - share_type: share_type_shares_response
   - links: links
   - is_public: is_public_shares_response
   - share_server_id: share_server_id
   - host: host_resource_response
   - snapshot_support: snapshot_support_share_capability
   - task_state: task_state
   - share_type_name: share_type_name
   - access_rules_status: access_rules_status
   - replication_type: replication_type_share_capability
   - has_replicas: has_replicas
   - user_id: share_user_id
   - create_share_from_snapshot_support: create_share_from_snapshot_support_share_capability
   - revert_to_snapshot_support: revert_to_snapshot_support_share_capability
   - share_group_id: share_group_id
   - source_share_group_snapshot_member_id: source_share_group_snapshot_member_id
   - mount_snapshot_support: mount_snapshot_support_share_capability
   - progress: progress_share_instance
   - count: count
   - volume_type: volume_type_shares_response
   - export_location: export_location
   - export_locations: export_locations
   - is_soft_deleted: is_soft_deleted_response
   - scheduled_to_be_deleted_at: scheduled_to_be_deleted_at_response

Response example
----------------

.. literalinclude:: samples/share-create-response.json
   :language: javascript


Manage share (since API v2.7)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/manage

.. versionadded:: 2.7

Use this API to bring a share under the management of the Shared File
Systems service.

Administrator only. Use the ``policy.yaml`` file to grant permissions for this
action to other roles.


.. note::

    Managing shares that are created on top of managed share servers (i.e. with
    parameter ``share_server_id``) is not supported prior to API version 2.49.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409
   - 422

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share: share
   - protocol: protocol
   - name: name_request
   - share_type: share_type_request
   - driver_options: driver_options
   - export_path: export_path
   - service_host: service_host
   - share_server_id: manage_share_server_id
   - is_public: is_public_manage_request
   - description: description_request

Request example
---------------

.. literalinclude:: samples/share-manage-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_id_response
   - size: size_response
   - availability_zone: availability_zone
   - created_at: created_at
   - status: share_status_response
   - name: name
   - description: description
   - project_id: project_id
   - snapshot_id: snapshot_id_shares_response
   - share_network_id: share_network_id
   - share_proto: share_proto
   - metadata: metadata
   - share_type: share_type_shares_response
   - links: links
   - is_public: is_public_shares_response
   - share_server_id: share_server_id
   - host: host_resource_response
   - snapshot_support: snapshot_support_share_capability
   - task_state: task_state
   - share_type_name: share_type_name
   - access_rules_status: access_rules_status
   - replication_type: replication_type_share_capability
   - has_replicas: has_replicas
   - user_id: managed_share_user_id
   - create_share_from_snapshot_support: create_share_from_snapshot_support_share_capability
   - revert_to_snapshot_support: revert_to_snapshot_support_share_capability
   - share_group_id: share_group_id
   - source_share_group_snapshot_member_id: source_share_group_snapshot_member_id
   - mount_snapshot_support: mount_snapshot_support_share_capability
   - progress: progress_share_instance
   - count: count
   - volume_type: volume_type_shares_response
   - export_location: export_location
   - export_locations: export_locations
   - is_soft_deleted: is_soft_deleted_response
   - scheduled_to_be_deleted_at: scheduled_to_be_deleted_at_response

Response example
----------------

.. literalinclude:: samples/share-manage-response.json
   :language: javascript


Update share
~~~~~~~~~~~~

.. rest_method::  PUT /v2/shares/{share_id}

Updates a share.

You can update these attributes:

- ``display_name``, which also changes the ``name`` of the share.

- ``display_description``, which also changes the ``description`` of
  the share.

- ``is_public``. Changes the level of visibility.

If you try to update other attributes, they retain their previous
values.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 422

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id
   - is_public: is_public_request
   - display_name: display_name_request
   - display_description: display_description_request

Request example
---------------

.. literalinclude:: samples/share-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_id_response
   - size: size_response
   - availability_zone: availability_zone
   - created_at: created_at
   - status: share_status_response
   - name: name
   - description: description
   - project_id: project_id
   - snapshot_id: snapshot_id_shares_response
   - share_network_id: share_network_id
   - share_proto: share_proto
   - metadata: metadata
   - share_type: share_type_shares_response
   - links: links
   - is_public: is_public_shares_response
   - share_server_id: share_server_id
   - host: host_resource_response
   - snapshot_support: snapshot_support_share_capability
   - task_state: task_state
   - share_type_name: share_type_name
   - access_rules_status: access_rules_status
   - replication_type: replication_type_share_capability
   - has_replicas: has_replicas
   - user_id: share_user_id
   - create_share_from_snapshot_support: create_share_from_snapshot_support_share_capability
   - revert_to_snapshot_support: revert_to_snapshot_support_share_capability
   - share_group_id: share_group_id
   - source_share_group_snapshot_member_id: source_share_group_snapshot_member_id
   - mount_snapshot_support: mount_snapshot_support_share_capability
   - progress: progress_share_instance
   - count: count
   - volume_type: volume_type_shares_response
   - export_location: export_location
   - export_locations: export_locations
   - is_soft_deleted: is_soft_deleted_response
   - scheduled_to_be_deleted_at: scheduled_to_be_deleted_at_response

Response example
----------------

.. literalinclude:: samples/share-update-response.json
   :language: javascript


Delete share
~~~~~~~~~~~~

.. rest_method::  DELETE /v2/shares/{share_id}

Deletes a share.

Preconditions

- Share status must be ``available``, ``error`` or ``inactive``

- You cannot already have a snapshot of the share.

- You cannot already have a group snapshot of the share.

- You cannot already have a replica of the share.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id
