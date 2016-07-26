.. -*- rst -*-

===============
Share snapshots
===============

Use the shared file service to make snapshots of shares. A share
snapshot is a point-in-time, read-only copy of the data that is
contained in a share. You can create, manage, update, and delete
share snapshots. After you create or manage a share snapshot, you
can create a share from it.

You can update a share snapshot to rename it, change its
description, or update its state to one of these supported states:

- ``available``

- ``error``

- ``creating``

- ``deleting``

- ``error_deleting``

- ``manage_starting``

- ``manage_error``

- ``unmanage_starting``

- ``unmanage_error``

As administrator, you can also reset the state of a snapshot and
force-delete a share snapshot in any state. Use the ``policy.json``
file to grant permissions for these actions to other roles.


List share snapshots
====================

.. rest_method::  GET /v2/{tenant_id}/snapshots

Lists all share snapshots.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_16
   - name: name_15

Response example
----------------

.. literalinclude:: samples/snapshots-list-response.json
   :language: javascript


List share snapshots with details
=================================

.. rest_method::  GET /v2/{tenant_id}/snapshots/detail

Lists all share snapshots with details.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_16
   - status: status_13
   - share_id: share_id_5
   - name: name_15
   - description: description_11
   - created_at: created_at_10
   - share_proto: share_proto_2
   - share_size: share_size
   - size: size_3

Response example
----------------

.. literalinclude:: samples/snapshots-list-detailed-response.json
   :language: javascript


Show share snapshot details
===========================

.. rest_method::  GET /v2/{tenant_id}/snapshots/{snapshot_id}

Shows details for a share snapshot.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - snapshot_id: snapshot_id_1

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_16
   - status: status_13
   - share_id: share_id_5
   - name: name_15
   - description: description_11
   - created_at: created_at_10
   - share_proto: share_proto_2
   - share_size: share_size
   - size: size_3

Response example
----------------

.. literalinclude:: samples/snapshot-show-response.json
   :language: javascript


Create share snapshot
=====================

.. rest_method::  POST /v2/{tenant_id}/snapshots

Creates a snapshot from a share.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - share_id: share_id_4
   - force: force
   - name: name_14
   - display_name: display_name_1
   - description: description_10
   - display_description: display_description_1

Request example
---------------

.. literalinclude:: samples/snapshot-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_16
   - share_id: share_id_5
   - status: status_13
   - name: name_15
   - description: description_11
   - created_at: created_at_10
   - share_proto: share_proto
   - share_size: share_size
   - provider_location: provider_location_1
   - size: size_3

Response example
----------------

.. literalinclude:: samples/snapshot-create-response.json
   :language: javascript


Manage share snapshot
=====================

.. rest_method::  POST /v2/{tenant_id}/snapshots/manage

(Since API v2.12) Configures Shared File Systems to manage a share snapshot.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - share_id: share_id_6
   - provider_location: provider_location
   - name: name
   - display_name: display_name_1
   - description: description
   - display_description: display_description_1
   - driver_options: driver_options

Request example
---------------

.. literalinclude:: samples/snapshot-manage-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_16
   - share_id: share_id_5
   - status: status_14
   - name: name_15
   - description: description_11
   - created_at: created_at_10
   - share_proto: share_proto
   - share_size: share_size
   - provider_location: provider_location_1
   - size: size_3

Response example
----------------

.. literalinclude:: samples/snapshot-manage-response.json
   :language: javascript


Unmanage share snapshot
=======================

.. rest_method::  POST /v2/{tenant_id}/snapshots/{snapshot_id}/action

(Since API v2.12) Configures Shared File Systems to stop managing a share snapshot.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - snapshot_id: snapshot_id_1
   - unmanage: unmanage

Request example
---------------

.. literalinclude:: samples/snapshot-actions-unmanage-request.json
   :language: javascript


Reset share snapshot state
==========================

.. rest_method::  POST /v2/{tenant_id}/snapshots/{snapshot_id}/action

Administrator only. Explicitly updates the state of a share snapshot.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - snapshot_id: snapshot_id_1
   - status: status_12

Request example
---------------

.. literalinclude:: samples/snapshot-actions-reset-state-request.json
   :language: javascript


Force-delete share snapshot
===========================

.. rest_method::  POST /v2/{tenant_id}/snapshots/{snapshot_id}/action

Administrator only. Force-deletes a share snapshot in any state.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - snapshot_id: snapshot_id_1
   - force_delete: force_delete_4

Request example
---------------

.. literalinclude:: samples/snapshot-actions-force-delete-request.json
   :language: javascript


Update share snapshot
=====================

.. rest_method::  PUT /v2/{tenant_id}/snapshots/{snapshot_id}

Updates a share snapshot.

You can update these attributes:

- ``display_name``, which also changes the ``name`` of the share
  snapshot.

- ``display_description``, which also changes the ``description`` of
  the share snapshot.

- ``is_public``. Changes the level of visibility.

If you try to update other attributes, they retain their previous
values.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - snapshot_id: snapshot_id_1
   - display_name: display_name_3
   - display_description: display_description_2

Request example
---------------

.. literalinclude:: samples/snapshot-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_16
   - status: status_13
   - share_id: share_id_5
   - name: name_15
   - description: description_11
   - created_at: created_at_10
   - share_proto: share_proto_2
   - share_size: share_size
   - size: size_3

Response example
----------------

.. literalinclude:: samples/snapshot-update-response.json
   :language: javascript


Delete share snapshot
=====================

.. rest_method::  DELETE /v2/{tenant_id}/snapshots/{snapshot_id}

Deletes a share snapshot.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - snapshot_id: snapshot_id_1
