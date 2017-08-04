.. -*- rst -*-

===================================
Share group types (since API v2.31)
===================================

A share group type enables you to filter or choose back ends before you
create a share group.

You can set share group types as either public or private. By default a
share group type is created as publicly accessible. Set
``share_group_type_access:is_public`` to ``False`` to make the share group
type private.

You can manage the access to the private share group types for the
different projects. You can add access, remove access, and get
information about access for a private share group type.

Administrators can specifies which `share type(s)
<http://developer.openstack.org/api-ref/shared-file-systems/#experimental-apis>`_
a given group type may contain. If Administrators does not specify it, then
manila will use ``default`` share type. The scheduler then creates the group on
one of the back ends that match the specified share type(s) and share group type.

Administrators can also set additional group extra specifications for a
share group type for the following purposes:

- Filter back ends by group scheduler. Specify these group extras specifications
  in this format: ``group_specs=value``. For example,
  ``consistent_snapshot_support=true``.

.. note::

    Share Group Types APIs are part of the `experimental APIs
    <http://developer.openstack.org/api-ref/shared-file-systems/#experimental-apis>`_.

List share group types
======================

.. rest_method::  GET /v2/{tenant_id}/share-group-types

Lists all share group types.

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_type_id_required
   - is_public: share_group_type_is_public
   - share_types: share_types_1
   - name: share_group_type_name
   - group_specs: group_specs_required

Response example
----------------

.. literalinclude:: samples/share-group-types-list-response.json
   :language: javascript


List default share group types
==============================

.. rest_method::  GET /v2/{tenant_id}/share-group-types/default

Lists default share group types.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path

Response parameters
-------------------
 
.. rest_parameters:: parameters.yaml

   - id: share_group_type_id_required
   - is_public: share_group_type_is_public
   - share_types: share_types_1
   - name: share_group_type_name
   - group_specs: group_specs_required

Response example
----------------

.. literalinclude:: samples/share-group-types-default-list-response.json
   :language: javascript


List share group types extra specs
==================================

.. rest_method::  GET /v2/{tenant_id}/share-group-types/{share_group_type_id}/group_specs

Lists the extra specifications for a share group type.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_group_type_id: share_group_type_id_required

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - group_specs: group_specs_required

Response example
----------------

.. literalinclude:: samples/share-group-types-group-specs-list-response.json
   :language: javascript


Create share group type
=======================

.. rest_method::  POST /v2/{tenant_id}/share-group-types

Creates a share group type.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_types: share_types_1
   - name: share_group_type_name
   - group_specs: group_specs
   - is_public: share_group_type_is_public_request

Request example
---------------

.. literalinclude:: samples/share-group-type-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_type_id_required
   - group_specs: group_specs_required
   - name: share_group_type_name
   - share_types: share_types_1
   - is_public: share_group_type_is_public

Response example
----------------

.. literalinclude:: samples/share-group-type-create-response.json
   :language: javascript


Show share group type access details
====================================

.. rest_method::  GET /v2/{tenant_id}/share-group-types/{share_group_type_id}/share_type_access

Shows access details for a share group type.

You can view access details for private share group types only.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_group_type_id: share_group_type_id_required

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_group_type_id: share_group_type_id_required
   - project_id: project_id_9

Response example
----------------

.. literalinclude:: samples/share-group-types-list-access-response.json
   :language: javascript


Set extra spec for share group type
===================================

.. rest_method::  POST /v2/{tenant_id}/share-group-types/{share_group_type_id}/group_specs

Sets an extra specification for the share group type.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_group_type_id: share_group_type_id_required
   - group_specs: group_specs_required

Request example
---------------

.. literalinclude:: samples/share-group-type-set-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - group_specs: group_specs_required

Response example
----------------

.. literalinclude:: samples/share-group-type-set-response.json
   :language: javascript


Unset an group spec
===================

.. rest_method::  DELETE /v2/{tenant_id}/share-group-types/{share_group_type_id}/group-specs/{group_spec_key}

Unsets an extra specification for the share type.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_group_type_id: share_group_type_id_required
   - group_spec_key: group_spec_key


Add share group type access
===========================

.. rest_method::  POST /v2/{tenant_id}/share-group-types/{share_group_type_id}/action

Adds share group type access for a project.

You can add access to private share group types only.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_group_type_id: share_group_type_id_path
   - project: project

Request example
---------------

.. literalinclude:: samples/share-group-type-grant-access-request.json
   :language: javascript


Remove share group type access
==============================

.. rest_method::  POST /v2/{tenant_id}/share-group-types/{share_group_type_id}/action

Removes share group type access from a project.

You can remove access from private share group types only.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_group_type_id: share_group_type_id_path
   - project: project

Request example
---------------

.. literalinclude:: samples/share-group-type-revoke-access-request.json
   :language: javascript


Delete share group type
=======================

.. rest_method::  DELETE /v2/{tenant_id}/share-group-types/{share_group_type_id}

Deletes a share group type.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_group_type_id: share_group_type_id_path
