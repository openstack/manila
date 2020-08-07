.. -*- rst -*-

======
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


List shares
===========

.. rest_method::  GET /v2/{project_id}/shares

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
   - limit: limit
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_4
   - links: links
   - name: name
   - count: count

Response example
----------------

.. literalinclude:: samples/shares-list-response.json
   :language: javascript


List shares with details
========================

.. rest_method::  GET /v2/{project_id}/shares/detail

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
   - limit: limit
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_type_name: share_type_name
   - links: links
   - availability_zone: availability_zone
   - share_network_id: share_network_id
   - export_locations: export_locations
   - share_server_id: share_server_id
   - snapshot_id: snapshot_id_share_response
   - id: id_4
   - size: size_2
   - share_type: share_type_1
   - export_location: export_location
   - project_id: project_id
   - metadata: metadata
   - status: status_16
   - progress: progress_share_instance
   - description: description
   - host: host_1
   - access_rules_status: access_rules_status
   - is_public: is_public
   - share_group_id: share_group_id
   - task_state: task_state
   - snapshot_support: snapshot_support
   - name: name
   - has_replicas: has_replicas
   - replication_type: replication_type
   - created_at: created_at
   - share_proto: share_proto
   - volume_type: volume_type
   - count: count
   - user_id: share_user_id

Response example
----------------

.. literalinclude:: samples/shares-list-detailed-response.json
   :language: javascript


Show share details
==================

.. rest_method::  GET /v2/{project_id}/shares/{share_id}

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

   - share_type_name: share_type_name
   - links: links
   - availability_zone: availability_zone_1
   - share_network_id: share_network_id
   - export_locations: export_locations
   - share_server_id: share_server_id
   - snapshot_id: snapshot_id_share_response
   - id: id_4
   - size: size_2
   - share_type: share_type_1
   - export_location: export_location
   - project_id: project_id
   - metadata: metadata
   - status: status_16
   - progress: progress_share_instance
   - description: description
   - host: host_9
   - access_rules_status: access_rules_status
   - is_public: is_public
   - share_group_id: share_group_id
   - task_state: task_state
   - snapshot_support: snapshot_support
   - name: name
   - has_replicas: has_replicas
   - replication_type: replication_type
   - created_at: created_at
   - share_proto: share_proto
   - volume_type: volume_type
   - user_id: share_user_id

Response example
----------------

.. literalinclude:: samples/share-show-response.json
   :language: javascript


Create share
============

.. rest_method::  POST /v2/{project_id}/shares

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
   - size: size
   - name: name_request
   - description: description_request
   - display_name: display_name_request
   - display_description: display_description_request
   - share_type: share_type
   - volume_type: volume_type
   - snapshot_id: snapshot_id_request
   - is_public: is_public
   - share_group_id: share_group_id_request
   - metadata: metadata
   - share_network_id: share_network_id_2
   - availability_zone: availability_zone

Request example
---------------

.. literalinclude:: samples/share-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_4
   - status: status_3
   - progress: progress_share_instance
   - links: links
   - project_id: project_id
   - share_proto: share_proto
   - size: size
   - name: name
   - description: description
   - share_type: share_type_1
   - share_type_name: share_share_type_name
   - has_replicas: has_replicas
   - replication_type: replication_type
   - volume_type: volume_type
   - snapshot_id: snapshot_id_share_response
   - is_public: is_public
   - share_group_id: share_group_id
   - metadata: metadata
   - share_network_id: share_network_id
   - availability_zone: availability_zone_1
   - export_location: export_location
   - export_locations: export_locations
   - host: host_1
   - task_state: task_state
   - share_server_id: share_server_id
   - snapshot_support: snapshot_support
   - created_at: created_at
   - user_id: share_user_id

Response example
----------------

.. literalinclude:: samples/share-create-response.json
   :language: javascript


Manage share (since API v2.7)
=============================

.. rest_method::  POST /v2/{project_id}/shares/manage

.. versionadded:: 2.7

Use this API to bring a share under the management of the Shared File
Systems service.

Administrator only. Use the ``policy.json`` file to grant permissions for this
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
   - share_type: share_type_2
   - driver_options: driver_options
   - export_path: export_path
   - service_host: service_host
   - share_server_id: manage_share_server_id
   - is_public: is_public
   - description: description_request

Request example
---------------

.. literalinclude:: samples/share-manage-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share: share
   - links: links
   - availability_zone: availability_zone_1
   - share_network_id: share_network_id
   - export_locations: export_locations
   - share_server_id: share_server_id
   - snapshot_id: snapshot_id_share_response
   - id: id_4
   - size: size_2
   - share_type: share_type_1
   - share_type_name: share_share_type_name
   - has_replicas: has_replicas
   - replication_type: replication_type
   - export_location: export_location
   - project_id: project_id
   - metadata: metadata
   - status: status_8
   - share_server_id: manage_share_server_id
   - description: description
   - host: host_9
   - is_public: is_public
   - share_group_id: share_group_id
   - snapshot_support: snapshot_support
   - name: name
   - created_at: created_at
   - share_proto: share_proto
   - volume_type: volume_type
   - user_id: managed_share_user_id

Response example
----------------

.. literalinclude:: samples/share-manage-response.json
   :language: javascript


Update share
============

.. rest_method::  PUT /v2/{project_id}/shares/{share_id}

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
   - is_public: is_public
   - display_name: display_name_request
   - display_description: display_description_request

Request example
---------------

.. literalinclude:: samples/share-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_type_name: share_share_type_name
   - links: links
   - availability_zone: availability_zone_1
   - share_network_id: share_network_id
   - export_locations: export_locations
   - share_server_id: share_server_id
   - snapshot_id: snapshot_id_share_response
   - id: id_4
   - size: size_2
   - share_type: share_type_1
   - export_location: export_location
   - project_id: project_id
   - metadata: metadata
   - status: status_16
   - description: description
   - host: host_9
   - access_rules_status: access_rules_status
   - is_public: is_public
   - share_group_id: share_group_id
   - task_state: task_state
   - snapshot_support: snapshot_support
   - name: name
   - has_replicas: has_replicas
   - replication_type: replication_type
   - created_at: created_at
   - share_proto: share_proto
   - volume_type: volume_type
   - user_id: share_user_id

Response example
----------------

.. literalinclude:: samples/share-update-response.json
   :language: javascript


Delete share
============

.. rest_method::  DELETE /v2/{project_id}/shares/{share_id}

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
