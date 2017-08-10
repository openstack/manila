.. -*- rst -*-

=========================================
Consistency groups (versions 2.4 to 2.30)
=========================================

Consistency groups enable you to create snapshots at the exact same
point in time from multiple file system shares. For example, a
database might place its tables, logs, and configuration on
separate shares. To restore this database from a previous point in
time, it makes sense to restore the logs, tables, and configuration
together from the exact same point in time.

As an administrator, you can also reset the state of a consistency
group and force-delete a consistency group in any state. Use the
``policy.json`` file to grant permissions for these actions to
other roles.

.. note::

    Consistency groups APIs are part of an ``experimental`` feature introduced
    in version 2.4. The APIs may change or be removed in further versions
    of the Shared File Systems API. All experimental APIs require the
    ``X-OpenStack-Manila-API-Experimental: True`` header to be sent in the
    requests.
    Consistency group APIs were removed in 2.31 API version. They were
    replaced with 'share groups' APIs.


List consistency groups
=======================

.. rest_method::  GET /v2/{tenant_id}/consistency-groups

Lists all consistency groups.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - all_tenants: cg_all_tenants_query
   - limit: cg_limit_query
   - offset: cg_offset_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - consistency_groups: consistency_groups
   - consistency_group: consistency_group
   - id: cg_id_response
   - name: cg_name_response
   - link: cg_links

Response example
----------------

.. literalinclude:: samples/consistency-group-list-response.json
   :language: javascript


List consistency groups with details
====================================

.. rest_method::  GET /v2/{tenant_id}/consistency-groups/detail

Lists all consistency groups with details.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - all_tenants: cg_all_tenants_query
   - limit: cg_limit_query
   - offset: cg_offset_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - consistency_groups: consistency_groups
   - consistency_group: consistency_group
   - id: cg_id_response
   - status: cg_status
   - links: cg_links
   - name: cg_name_response
   - description: cg_description_response
   - source_cgsnapshot_id: cg_snapshot_id
   - created_at: cg_created_at
   - share_network_id: cg_share_network_id
   - host: cg_host
   - project_id: cg_project_id
   - share_server_id: cg_share_server_id
   - share_types: cg_share_types_response

Response example
----------------

.. literalinclude:: samples/consistency-group-list-detail-response.json
   :language: javascript


Show consistency group details
==============================

.. rest_method::  GET /v2/{tenant_id}/consistency-groups/{consistency_group_id}

Shows details for a consistency group.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - consistency_group_id: cg_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - consistency_group: consistency_group
   - id: cg_id_response
   - status: cg_status
   - links: cg_links
   - name: cg_name_response
   - description: cg_description_response
   - source_cgsnapshot_id: cg_snapshot_id
   - created_at: cg_created_at
   - share_network_id: cg_share_network_id
   - host: cg_host
   - project_id: cg_project_id
   - share_server_id: cg_share_server_id
   - share_types: cg_share_types_response

Response example
----------------

.. literalinclude:: samples/consistency-group-show-response.json
   :language: javascript


Create consistency group
========================

.. rest_method::  POST /v2/{tenant_id}/consistency-groups

Creates a consistency group.


Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
conflict(409)


Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_types: cg_share_types_request
   - name: cg_name_request
   - description: cg_description_request
   - share_network_id: cg_share_network_id
   - source_cgsnapshot_id: cg_snapshot_id

Request example
---------------

.. literalinclude:: samples/consistency-group-create-request.json
   :language: javascript


Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - consistency_group: consistency_group
   - id: cg_id_response
   - status: cg_status
   - links: cg_links
   - name: cg_name_response
   - description: cg_description_response
   - source_cgsnapshot_id: cg_snapshot_id
   - created_at: cg_created_at
   - share_network_id: cg_share_network_id
   - host: cg_host
   - project_id: cg_project_id
   - share_server_id: cg_share_server_id
   - share_types: cg_share_types_response


Response example
----------------

.. literalinclude:: samples/consistency-group-create-response.json
   :language: javascript


Update consistency group
========================

.. rest_method::  PUT /v2/{tenant_id}/consistency-groups/{consistency_group_id}

Updates a consistency group.

You can update only these attributes:

- ``name``, which changes the consistency group name.

- ``description``, which changes the consistency group description.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id
   - consistency_group_id: cg_id_path
   - name: cg_name_request
   - description: cg_description_request

Request example
---------------

.. literalinclude:: samples/consistency-group-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - consistency_group: consistency_group
   - id: cg_id_response
   - status: cg_status
   - links: cg_links
   - name: cg_name_response
   - description: cg_description_response
   - source_cgsnapshot_id: cg_snapshot_id
   - created_at: cg_created_at
   - share_network_id: share_network_id
   - host: cg_host
   - project_id: cg_project_id
   - share_server_id: cg_share_server_id
   - share_types: cg_share_types_response

Response example
----------------

.. literalinclude:: samples/consistency-group-update-response.json
   :language: javascript


Reset consistency group state
=============================

.. rest_method::  POST /v2/{tenant_id}/consistency-groups/{consistency_group_id}/action

Administrator only. Explicitly updates the state of a consistency group.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - consistency_group_id: cg_id_path
   - reset_status: reset_status
   - os-reset_status: os-reset_status
   - status: status

Request example
---------------

.. literalinclude:: samples/consistency-group-reset_status-request.json
   :language: javascript


Force-delete consistency group
==============================

.. rest_method::  POST /v2/{tenant_id}/consistency-groups/{consistency_group_id}/action

Administrator only. Force-deletes a consistency group.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - consistency_group_id: cg_id_path
   - os-force_delete: os-force_delete
   - force_delete: force_delete

Request example
---------------

.. literalinclude:: samples/consistency-group-force_delete-request.json
   :language: javascript

Delete consistency group
========================

.. rest_method::  DELETE /v2/{tenant_id}/consistency-groups/{consistency_group_id}

Deletes a consistency group.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - consistency_group_id: cg_id_path
