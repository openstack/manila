.. -*- rst -*-

=======================================
Share group snapshots (since API v2.31)
=======================================

Use the shared file service to make snapshots of share groups. A share
group snapshot is a point-in-time, read-only copy of the data that is
contained in a share group. You can create, update, and delete
share group snapshots. After you create a share group snapshot, you
can create a share group from it.

You can update a share group snapshot to rename it, change its
description, or update its state.

As administrator, you can also reset the state of a group snapshot. Use
the ``policy.json`` file to grant permissions for these actions to other
roles.

.. note::

    Share Group Snapshot APIs are part of the `experimental APIs
    <http://developer.openstack.org/api-ref/shared-file-systems/#experimental-apis>`_.

List share group snapshots
==========================

.. rest_method::  GET /v2/{tenant_id}/share-group-snapshots

Lists all share group snapshots.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - project_id: project_id
   - all_tenants: all_tenants
   - name: group_snapshot_name_query
   - description: group_snapshot_description_query
   - status: group_snapshot_status_query
   - share_group_id: share_group_id_query
   - limit: limit_query
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - name: snapshot_name
   - links: group_snapshot_links

Response example
----------------

.. literalinclude:: samples/share-group-snapshots-list-response.json
   :language: javascript


List share group snapshots with details
=======================================

.. rest_method::  GET /v2/{tenant_id}/share-group-snapshots/detail

Lists all share group snapshots with details.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - project_id: project_id
   - all_tenants: all_tenants
   - name: group_snapshot_name_query
   - description: group_snapshot_description_query
   - status: group_snapshot_status_query
   - share_group_id: share_group_id_query
   - limit: limit_query
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - project_id: project_id
   - status: group_snapshot_status_required
   - share_group_id: share_group_id
   - name: group_snapshot_name
   - description: group_snapshot_description
   - created_at: group_snapshot_created_at
   - members: group_snapshot_members
   - links: group_snapshot_links

Response example
----------------

.. literalinclude:: samples/share-group-snapshots-list-detailed-response.json
   :language: javascript


List share group snapshots members
==================================

.. rest_method::  GET /v2/{tenant_id}/share-group-snapshots/{group_snapshot_id}/members

Lists all share group snapshots members.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - group_snapshot_id: group_snapshot_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - created_at: snapshot_created_at
   - project_id: project_id
   - size: snapshot_size
   - share_protocol: snapshot_share_protocol
   - name: snapshot_name
   - share_group_snapshot_id: group_snapshot_id
   - share_id: snapshot_share_id


Response example
----------------

.. literalinclude:: samples/share-group-snapshots-list-members-response.json
   :language: javascript


Show share group snapshot details
=================================

.. rest_method::  GET /v2/{tenant_id}/share-group-snapshots/{group_snapshot_id}

Shows details for a share group snapshot.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - group_snapshot_id: group_snapshot_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - project_id: project_id
   - status: group_snapshot_status_required
   - share_group_id: share_group_id
   - name: group_snapshot_name
   - description: group_snapshot_description
   - created_at: group_snapshot_created_at
   - members: group_snapshot_members
   - links: group_snapshot_links

Response example
----------------

.. literalinclude:: samples/share-group-snapshot-show-response.json
   :language: javascript


Create share group snapshot
===========================

.. rest_method::  POST /v2/{tenant_id}/share-group-snapshots

Creates a snapshot from a share.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - name: group_snapshot_name_option
   - description: group_snapshot_description_option
   - share_group_id: share_group_id

Request example
---------------

.. literalinclude:: samples/share-group-snapshot-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - project_id: project_id
   - status: group_snapshot_status_required
   - share_group_id: share_group_id
   - name: group_snapshot_name
   - description: group_snapshot_description
   - created_at: group_snapshot_created_at
   - members: group_snapshot_members
   - links: group_snapshot_links

Response example
----------------

.. literalinclude:: samples/share-group-snapshot-create-response.json
   :language: javascript


Reset share group snapshot state
================================

.. rest_method::  POST /v2/{tenant_id}/share-group-snapshots/{group_snapshot_id}/action

Administrator only. Explicitly updates the state of a share group snapshot.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - group_snapshot_id: group_snapshot_id_path
   - status: group_snapshot_status_required

Request example
---------------

.. literalinclude:: samples/snapshot-actions-reset-state-request.json
   :language: javascript


Update share group snapshot
===========================

.. rest_method::  PUT /v2/{tenant_id}/share-group-snapshots/{group_snapshot_id}

Updates a share group snapshot.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - group_snapshot_id: group_snapshot_id_path
   - name: group_snapshot_name_option
   - description: group_snapshot_description_option

Request example
---------------

.. literalinclude:: samples/snapshot-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - project_id: project_id
   - status: group_snapshot_status_required
   - share_group_id: share_group_id
   - name: group_snapshot_name
   - description: group_snapshot_description
   - created_at: group_snapshot_created_at
   - members: group_snapshot_members
   - links: group_snapshot_links

Response example
----------------

.. literalinclude:: samples/share-group-snapshot-update-response.json
   :language: javascript


Delete share group snapshot
===========================

.. rest_method::  DELETE /v2/{tenant_id}/share-group-snapshots/{group_snapshot_id}

Deletes a share group snapshot.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - group_snapshot_id: group_snapshot_id_path
