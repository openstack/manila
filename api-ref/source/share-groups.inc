.. -*- rst -*-

==============================
Share groups (since API v2.31)
==============================

The share groups enable you to create a group of volumes and manage them
together. A project can put shares be used in the same application together
in a share group, such as consistency group snapshot, clone, backup, migrate,
replicate, retype, etc.

Shares should be able to become a part of a share group only on share creation
step. If share was created without provided ``share_group_id`` then this share
won't be able to become a part of any share group.

You can create a share group and associate it with multiple shares, list
share groups, and show information for delete a share group.

.. note::

    Share Group APIs are part of the `experimental APIs
    <http://developer.openstack.org/api-ref/shared-file-systems/#experimental-apis>`_.
    The ``availability_zone_id`` and ``consistent_snapshot_support`` fields were added
    to ``share_group`` object introduced in version 2.34.

List share groups
=================

.. rest_method::  GET /v2/{tenant_id}/share_groups

Lists all share groups.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id
   - project_id: project_id
   - all_tenants: all_tenants
   - name: name_query
   - description: description_query
   - status: share_group_status_query
   - share_server_id: share_server_id_query
   - snapshot_id: snapshot_id_query
   - host: backend_host_query
   - share_network_id: share_network_id_query
   - share_group_type_id: share_group_type_id_query
   - limit: limit_query
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir
   - name~: name_inexact_query
   - description~: description_inexact_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_id
   - links: share_group_links
   - name: share_group_name_response
   - status: share_group_status
   - description: share_group_description_response

Response example
----------------

.. literalinclude:: samples/share-groups-list-response.json
   :language: javascript


Show share group details
========================

.. rest_method::  GET /v2/{tenant_id}/share_groups/{share_group_id}

Shows details for a share group.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - share_group_id: share_group_id_path
   - tenant_id: tenant_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_id
   - name: share_group_name_response
   - created_at: share_group_created_at
   - status: share_group_status
   - description: share_group_description_response
   - project_id: project_id
   - host: backend_host
   - share_group_type_id: share_group_type_id_required
   - source_share_group_snapshot_id: source_share_group_snapshot_id_response
   - share_network_id: share_network_id
   - share_types: share_types_1
   - links: share_group_links
   - availability_zone: availability_zone_id_2
   - consistent_snapshot_support: consistent_snapshot_support

Response example
----------------

.. literalinclude:: samples/share-group-show-response.json
   :language: javascript


Create share group
==================

.. rest_method::  POST /v2/{tenant_id}/share_groups

Creates a share group.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - name: share_group_name
   - description: share_group_description
   - share_types: share_types
   - share_group_type: share_group_type_id
   - share_network: share_network_id_1
   - source_share_group_snapshot: source_share_group_snapshot_id
   - availability_zone: availability_zone_id_2

Request example
---------------

.. literalinclude:: samples/share-group-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_id
   - name: share_group_name_response
   - created_at: share_group_created_at
   - status: share_group_status
   - description: share_group_description_response
   - project_id: project_id
   - host: share_group_host
   - share_group_type_id: share_group_type_id_required
   - source_share_group_snapshot_id: source_share_group_snapshot_id_response
   - share_network_id: share_network_id
   - share_types: share_types_1
   - links: share_group_links
   - availability_zone: availability_zone_id_2
   - consistent_snapshot_support: consistent_snapshot_support

Response example
----------------

.. literalinclude:: samples/share-group-create-response.json
   :language: javascript


Reset share group state
=======================

.. rest_method::  POST /v2/{tenant_id}/share-groups/{share_group_id}/action

Administrator only. Explicitly updates the state of a share group.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - reset_status: reset_status
   - status: share_group_status
   - share_group_id: share_group_id_path
   - tenant_id: tenant_id_path

Request example
---------------

.. literalinclude:: samples/share-group-reset-state-request.json
   :language: javascript


Update share group
==================

.. rest_method::  PUT /v2/{tenant_id}/share-groups/{share_group_id}

Updates a share group.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - display_name: share_group_name
   - display_description: share_group_description
   - share_group_id: share_group_id_path
   - tenant_id: tenant_id_path

Request example
---------------

.. literalinclude:: samples/share-group-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_id
   - name: share_group_name_response
   - created_at: share_group_created_at
   - status: share_group_status
   - description: share_group_description_response
   - project_id: project_id
   - host: share_group_host
   - share_group_type_id: share_group_type_id_required
   - source_share_group_snapshot_id: source_share_group_snapshot_id
   - share_network_id: share_network_id
   - share_types: share_types_1
   - links: share_group_links
   - availability_zone: availability_zone_id_2
   - consistent_snapshot_support: consistent_snapshot_support

Response example
----------------

.. literalinclude:: samples/share-group-update-response.json
   :language: javascript


Delete share group
==================

.. rest_method::  DELETE /v2/{tenant_id}/share-groups/{share_group_id}

Deletes a share group.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - share_group_id: share_group_id_path
   - tenant_id: tenant_id_path
   - force: share_force_delete
