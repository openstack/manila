.. -*- rst -*-

======
Shares
======

A share is a remote, mountable file system. You can mount a share
to and access a share from several hosts by several users at a
time.

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

.. rest_method::  GET /v2/{tenant_id}/shares

Lists all shares.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - all_tenants: all_tenants
   - name: name_5
   - status: status_6
   - share_server_id: share_server_id
   - metadata: metadata
   - extra_specs: extra_specs
   - share_type_id: share_type_id
   - limit: limit
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir
   - snapshot_id: snapshot_id_query
   - host: host_1
   - share_network_id: share_network_id
   - project_id: project_id_6
   - is_public: is_public
   - share_group_id: share_group_id_query
   - export_location_id: export_location_id_query
   - export_location_path: export_location_path_query
   - name~: name_inexact_query
   - description~: description_inexact_query
   - with_count: with_count

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

.. rest_method::  GET /v2/{tenant_id}/shares/detail

Lists all shares, with details.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - all_tenants: all_tenants
   - name: name_5
   - status: status_6
   - share_server_id: share_server_id
   - metadata: metadata
   - extra_specs: extra_specs
   - share_type_id: share_type_id
   - limit: limit
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir
   - snapshot_id: snapshot_id_query
   - host: host_1
   - share_network_id: share_network_id
   - project_id: project_id_6
   - is_public: is_public
   - share_group_id: share_group_id_query
   - export_location_id: export_location_id_query
   - export_location_path: export_location_path_query
   - name~: name_inexact_query
   - description~: description_inexact_query
   - with_count: with_count

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
   - project_id: project_id_4
   - metadata: metadata
   - status: status_16
   - description: description_5
   - host: host_1
   - access_rules_status: access_rules_status
   - is_public: is_public
   - share_group_id: share_group_id
   - task_state: task_state
   - snapshot_support: snapshot_support
   - name: name_5
   - has_replicas: has_replicas
   - replication_type: replication_type
   - created_at: created_at_4
   - share_proto: share_proto
   - volume_type: volume_type
   - count: count

Response example
----------------

.. literalinclude:: samples/shares-list-detailed-response.json
   :language: javascript


Show share details
==================

.. rest_method::  GET /v2/{tenant_id}/shares/{share_id}

Shows details for a share.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - share_id: share_id
   - tenant_id: tenant_id_path

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
   - project_id: project_id_4
   - metadata: metadata
   - status: status_16
   - description: description_5
   - host: host_9
   - access_rules_status: access_rules_status
   - is_public: is_public
   - share_group_id: share_group_id
   - task_state: task_state
   - snapshot_support: snapshot_support
   - name: name_5
   - has_replicas: has_replicas
   - replication_type: replication_type
   - created_at: created_at_4
   - share_proto: share_proto
   - volume_type: volume_type

Response example
----------------

.. literalinclude:: samples/share-show-response.json
   :language: javascript


Create share
============

.. rest_method::  POST /v2/{tenant_id}/shares

Creates a share.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_proto: share_proto
   - size: size
   - name: name_5
   - description: description_5
   - display_name: display_name
   - display_description: display_description
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
   - links: links
   - project_id: project_id
   - share_proto: share_proto
   - size: size
   - name: name_5
   - description: description_5
   - display_name: display_name
   - display_description: display_description
   - share_type: share_type_1
   - share_type_name: share_type_name
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
   - created_at: created_at_4

Response example
----------------

.. literalinclude:: samples/share-create-response.json
   :language: javascript


Manage share
============

.. rest_method::  GET /v2/{tenant_id}/shares/manage

Configures Shared File Systems to manage a share.
This API is available for API versions later than or equal to 2.7

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share: share
   - protocol: protocol
   - name: name_5
   - share_type: share_type_2
   - driver_options: driver_options
   - export_path: export_path
   - service_host: service_host
   - is_public: is_public
   - description: description_5

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
   - share_type_name: share_type_name
   - has_replicas: has_replicas
   - replication_type: replication_type
   - export_location: export_location
   - project_id: project_id_4
   - metadata: metadata
   - status: status_8
   - description: description_5
   - host: host_9
   - is_public: is_public
   - share_group_id: share_group_id
   - snapshot_support: snapshot_support
   - name: name_5
   - created_at: created_at_4
   - share_proto: share_proto
   - volume_type: volume_type

Response example
----------------

.. literalinclude:: samples/share-manage-response.json
   :language: javascript


Update share
============

.. rest_method::  PUT /v2/{tenant_id}/shares/{share_id}

Updates a share.

You can update these attributes:

- ``display_name``, which also changes the ``name`` of the share.

- ``display_description``, which also changes the ``description`` of
  the share.

- ``is_public``. Changes the level of visibility.

If you try to update other attributes, they retain their previous
values.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - is_public: is_public
   - display_name: display_name_3
   - display_description: display_description_3
   - share_id: share_id
   - tenant_id: tenant_id_path

Request example
---------------

.. literalinclude:: samples/share-update-request.json
   :language: javascript

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
   - project_id: project_id_4
   - metadata: metadata
   - status: status_16
   - description: description_5
   - host: host_9
   - access_rules_status: access_rules_status
   - is_public: is_public
   - share_group_id: share_group_id
   - task_state: task_state
   - snapshot_support: snapshot_support
   - name: name_5
   - has_replicas: has_replicas
   - replication_type: replication_type
   - created_at: created_at_4
   - share_proto: share_proto
   - volume_type: volume_type

Response example
----------------

.. literalinclude:: samples/share-update-response.json
   :language: javascript


Delete share
============

.. rest_method::  DELETE /v2/{tenant_id}/shares/{share_id}

Deletes a share.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - share_id: share_id
   - tenant_id: tenant_id_path
