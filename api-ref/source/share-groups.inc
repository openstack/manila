.. -*- rst -*-

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

    Share Group APIs are no longer considered experimental since API version
    2.55. The ``availability_zone_id`` and ``consistent_snapshot_support``
    fields were added to ``share_group`` object since version 2.34.

List share groups
~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-groups

.. versionadded:: 2.31

Lists all share groups.

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
   - description: description_query
   - status: share_group_status_query
   - share_server_id: share_server_id_query
   - snapshot_id: snapshot_id_query
   - host: backend_host_query
   - share_network_id: share_network_id_query
   - share_group_type_id: share_group_type_id_query
   - share_group_snapshot_id: source_share_group_snapshot_id_query
   - share_types: share_types_query
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
   - name: name
   - status: share_group_status
   - description: description

Response example
----------------

.. literalinclude:: samples/share-groups-list-response.json
   :language: javascript

List share groups with details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-groups/detail

.. versionadded:: 2.31

Lists all share groups with details.

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
   - description: description_query
   - status: share_group_status_query
   - share_server_id: share_server_id_query
   - snapshot_id: snapshot_id_query
   - host: backend_host_query
   - share_network_id: share_network_id_query
   - share_group_type_id: share_group_type_id_query
   - share_group_snapshot_id: source_share_group_snapshot_id_query
   - share_types: share_types_query
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
   - name: name
   - created_at: created_at
   - status: share_group_status
   - description: description
   - project_id: project_id
   - host: backend_host
   - share_group_type_id: share_group_type_id_required
   - source_share_group_snapshot_id: source_share_group_snapshot_id_response
   - share_network_id: share_network_id
   - share_types: share_types_1
   - links: share_group_links
   - availability_zone: availability_zone_id_share_group
   - consistent_snapshot_support: consistent_snapshot_support

Response example
----------------

.. literalinclude:: samples/share-groups-list-detailed-response.json
   :language: javascript


Show share group details
~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-groups/{share_group_id}

.. versionadded:: 2.31

Shows details for a share group.


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
   - share_group_id: share_group_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_id
   - name: name
   - created_at: created_at
   - status: share_group_status
   - description: description
   - project_id: project_id
   - host: backend_host
   - share_group_type_id: share_group_type_id_required
   - source_share_group_snapshot_id: source_share_group_snapshot_id_response
   - share_network_id: share_network_id
   - share_types: share_types_1
   - links: share_group_links
   - availability_zone: availability_zone_id_share_group
   - consistent_snapshot_support: consistent_snapshot_support

Response example
----------------

.. literalinclude:: samples/share-group-show-response.json
   :language: javascript


Create share group
~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-groups

.. versionadded:: 2.31

Creates a share group.

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
   - name: name_request
   - description: description_request
   - share_types: share_types
   - share_group_type: share_group_type_id
   - share_network: share_network_id_request
   - source_share_group_snapshot: source_share_group_snapshot_id
   - availability_zone: availability_zone_id_share_group

Request example
---------------

.. literalinclude:: samples/share-group-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_id
   - name: name
   - created_at: created_at
   - status: share_group_status
   - description: description
   - project_id: project_id
   - host: share_group_host
   - share_group_type_id: share_group_type_id_required
   - source_share_group_snapshot_id: source_share_group_snapshot_id_response
   - share_network_id: share_network_id
   - share_types: share_types_1
   - links: share_group_links
   - availability_zone: availability_zone_id_share_group
   - consistent_snapshot_support: consistent_snapshot_support

Response example
----------------

.. literalinclude:: samples/share-group-create-response.json
   :language: javascript


Reset share group state
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-groups/{share_group_id}/action

.. versionadded:: 2.31

Administrator only. Explicitly updates the state of a share group.

Use the ``policy.yaml`` file to grant permissions for this action
to other roles.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_group_id: share_group_id_path
   - reset_status: reset_status
   - status: share_group_status


Request example
---------------

.. literalinclude:: samples/share-group-reset-state-request.json
   :language: javascript


Update share group
~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/share-groups/{share_group_id}

.. versionadded:: 2.31

Updates a share group.

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
   - share_group_id: share_group_id_path
   - name: name_request
   - description: description_request


Request example
---------------

.. literalinclude:: samples/share-group-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_id
   - name: name
   - created_at: created_at
   - status: share_group_status
   - description: description
   - project_id: project_id
   - host: share_group_host
   - share_group_type_id: share_group_type_id_required
   - source_share_group_snapshot_id: source_share_group_snapshot_id
   - share_network_id: share_network_id
   - share_types: share_types_1
   - links: share_group_links
   - availability_zone: availability_zone_id_share_group
   - consistent_snapshot_support: consistent_snapshot_support

Response example
----------------

.. literalinclude:: samples/share-group-update-response.json
   :language: javascript


Delete share group
~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-groups/{share_group_id}

.. versionadded:: 2.31

Deletes a share group.

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
   - share_group_id: share_group_id_path
   - force: share_force_delete
