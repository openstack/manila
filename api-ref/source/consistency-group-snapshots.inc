.. -*- rst -*-

==================================================
Consistency group snapshots (versions 2.4 to 2.30)
==================================================

You can create snapshots of consistency groups. To create a
snapshot, you specify the ID of the consistency group that you want
to snapshot. After you create a consistency group snapshot, you can
create a consistency group from it.

A consistency group snapshot can have member shares. To add a
member share, include the ``consistency_group_id`` parameter in the
create share request. This ID must match the ID of the consistency
group from which the consistency group snapshot was created. Then,
when you use consistency group snapshots to restore data, you can
easily determine which shares belong to a consistency group.

As an administrator, you can also reset the state of a consistency
group snapshot and ``force-delete`` a consistency group snapshot in any
state. Use the ``policy.json`` file to grant permissions for these
actions to other roles.

.. note::

    Consistency group snapshot APIs are part of the `experimental APIs
    <http://developer.openstack.org/api-ref/shared-file-systems/
    #experimental-apis>`_.
    Consistency group snapshot APIs were removed in 2.31 API version. They
    were replaced with 'share groups' APIs.


List consistency group snapshots
================================

.. rest_method::  GET /v2/{tenant_id}/cgsnapshots

Lists all consistency group snapshots.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)


Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - limit: limit_2
   - offset: offset_2
   - all_tenants: all_tenants_2


Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - cgsnapshots: cgsnapshots
   - cgsnapshot: cgsnapshot
   - id: id_1
   - name: name_8
   - cgsnapshot_links: cgsnapshot_links


Response example
----------------

.. literalinclude:: samples/consistency-group-snapshot-list-response.json
   :language: javascript


List consistency group snapshots with details
=============================================

.. rest_method::  GET /v2/{tenant_id}/cgsnapshots/detail

Lists all consistency group snapshots with details.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)


Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - limit: limit_2
   - offset: offset_2
   - all_tenants: all_tenants_2


Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - cgsnapshots: cgsnapshots
   - cgsnapshot: cgsnapshot
   - id: id_1
   - status: status
   - links: links
   - project_id: project_id_1
   - consistency_group_id: consistency_group_id_4
   - name: name_8
   - description: description_7
   - created_at: created_at_1
   - cgsnapshot_links: cgsnapshot_links


Response example
----------------

.. literalinclude:: samples/consistency-group-snapshot-list-detail-response.json
   :language: javascript


Show consistency group snapshot details
=======================================

.. rest_method::  GET /v2/{tenant_id}/cgsnapshots/{cgsnapshot_id}

Shows details for a consistency group snapshot.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - cgsnapshot_id: cgsnapshot_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - cgsnapshot: cgsnapshot
   - id: id_1
   - status: status
   - links: links
   - project_id: project_id_1
   - consistency_group_id: consistency_group_id_4
   - name: name_8
   - description: description_7
   - created_at: created_at_1
   - cgsnapshot_links: cgsnapshot_links

Response example
----------------

.. literalinclude:: samples/consistency-group-snapshot-show-response.json
   :language: javascript


List consistency group snapshot members
=======================================

.. rest_method::  GET /v2/{tenant_id}/cgsnapshots/{cgsnapshot_id}/members

Shows information about a consistency group snapshot member.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - cgsnapshot_id: cgsnapshot_id_1
   - limit: limit_3
   - offset: offset_3

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - cgsnapshot_members: cgsnapshot_members
   - id: id_10
   - share_id: share_id_1
   - share_type_id: share_type_id_1
   - created_at: created_at_8
   - cgsnapshot_id: cgsnapshot_id_1
   - share_protocol: share_protocol
   - project_id: project_id_5
   - size: size_1
   - cgsnapshot_members_links: cgsnapshot_members_links

Response example
----------------

.. literalinclude:: samples/consistency-group-member-list-response.json
   :language: javascript


Create consistency group snapshot
=================================

.. rest_method::  POST /v2/{tenant_id}/cgsnapshots

Creates a consistency group snapshot.

You can create a consistency group snapshot for a consistency group
in ``available`` state only.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - consistency_group_id: consistency_group_id
   - name: name_1
   - description: description_1

Request example
---------------

.. literalinclude:: samples/consistency-group-snapshot-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - cgsnapshot: cgsnapshot
   - id: id_1
   - status: status
   - links: links
   - project_id: project_id_1
   - consistency_group_id: consistency_group_id_4
   - name: name_8
   - description: description_7
   - created_at: created_at_1
   - cgsnapshot_links: cgsnapshot_links

Response example
----------------

.. literalinclude:: samples/consistency-group-snapshot-create-response.json
   :language: javascript

Reset consistency group snapshot state
======================================

.. rest_method::  POST /v2/{tenant_id}/cgsnapshots/{cgsnapshot_id}/action

Administrator only. Explicitly updates the state of a consistency group
snapshot.

Administrators can use the ``policy.json`` file to permit other
roles to complete this action.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - cgsnapshot_id: cgsnapshot_id
   - reset_status: reset_status
   - os-reset_status: os-reset_status
   - status: status

Request example
---------------

.. literalinclude:: samples/consistency-group-snapshot-reset_status-request.json
   :language: javascript


Force-delete consistency group snapshot
=======================================

.. rest_method::  POST /v2/{tenant_id}/cgsnapshots/{cgsnapshot_id}/action

Administrator only. Force-deletes a consistency group snapshot.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)


Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - cgsnapshot_id: cgsnapshot_id_1
   - force_delete: force_delete

Request example
---------------

.. literalinclude:: samples/consistency-group-snapshot-force_delete-request.json
   :language: javascript


Update consistency group snapshot
=================================

.. rest_method::  PUT /v2/{tenant_id}/cgsnapshots/{cgsnapshot_id}

Updates a consistency group snapshot.

You can update only these attributes:

- ``name``, which changes the consistency group snapshot name.

- ``description``, which changes the consistency group snapshot
  description.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - cgsnapshot_id: cgsnapshot_id_1
   - name: name_1
   - description: description_1

Request example
---------------

.. literalinclude:: samples/consistency-group-snapshot-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - cgsnapshot: cgsnapshot
   - id: id_1
   - status: status
   - links: links
   - project_id: project_id_1
   - consistency_group_id: consistency_group_id_4
   - name: name_8
   - description: description_7
   - created_at: created_at_1
   - cgsnapshot_links: cgsnapshot_links

Response example
----------------

.. literalinclude:: samples/consistency-group-snapshot-update-response.json
   :language: javascript


Delete consistency group snapshot
=================================

.. rest_method::  DELETE /v2/{tenant_id}/cgsnapshots/{cgsnapshot_id}

Deletes a consistency group snapshot.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - cgsnapshot_id: cgsnapshot_id_1
