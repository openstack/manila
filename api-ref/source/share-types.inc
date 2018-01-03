.. -*- rst -*-

===========
Share types
===========

A share type enables you to filter or choose back ends before you
create a share. A share type behaves in the same way as a Block
Storage volume type behaves.

You set a share type to private or public and manage the access to
the private share types.

When you issue a create a share type request, you can submit a
request body with either a ``share_type`` or ``volume_type``
object.

.. important::

    The use of the ``volume_type`` object is deprecated but supported. It is
    recommended that you use the ``share_type`` object when you create a
    share type.

No matter which object type you include in the request, the API
creates both a ``volume_type`` object and a ``share_type`` object.
Both objects have the same ID. When you issue a list share types
request, the response shows both ``share_type`` and ``volume_type`` objects.

You can set share types as either public or private. By default a
share type is created as publicly accessible. Set
``share_type_access:is_public`` (``os-share-type-access:is_public``
for API versions 1.0-2.6) to ``False`` to make the share type
private.

You can manage the access to the private share types for the
different projects. You can add access, remove access, and get
information about access for a private share type.

Administrators can create share types with these extra
specifications that are used to filter back ends:

- ``driver_handles_share_servers``. Required. Defines the driver
  mode for share server, or storage, life cycle management. The
  Shared File Systems service creates a share server for the export
  of shares.

  Set to ``True`` when the share driver manages or handles the
  share server life cycle.

  Set to ``False`` when an administrator rather than a share driver
  manages the share server life cycle.

- ``snapshot_support``. Filters back ends by whether they do or do
  not support share snapshots.

  Set to ``True`` to find back ends that support share snapshots.

  Set to ``False`` to find back ends that do not support share
  snapshots.

Administrators can also set additional extra specifications for a
share type for the following purposes:

- Filter back ends. Specify these unqualified extra specifications
  in this format: ``extra_spec=value``. For example,
  ``netapp_raid_type=raid4``.

- Set data for the driver. Except for the special ``capabilities``
  prefix, you specify these qualified extra specifications with its
  prefix followed by a colon: ``vendor:extra_spec=value``. For
  example, ``netapp:thin_provisioned=true``.

The scheduler uses the special ``capabilities`` prefix for
filtering. The scheduler can only create a share on a back end that
reports capabilities that match the un-scoped extra-spec keys for
the share type. For details, see `Capabilities and Extra-Specs
<https://docs.openstack.org/manila/latest/admin/
capabilities_and_extra_specs.html>`_.

Each driver implementation determines which extra specification
keys it uses. For details, see the documentation for the driver.

An administrator can use the ``policy.json`` file to grant
permissions for share type creation with extra specifications to
other roles.


List share types
================

.. rest_method::  GET /v2/{tenant_id}/types

Lists all share types.

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_type_id_body
   - name: share_type_name
   - required_extra_specs: required_extra_specs
   - extra_specs: extra_specs
   - driver_handles_share_servers: driver_handles_share_servers
   - replication_type: replication_type
   - snapshot_support: snapshot_support_1
   - mount_snapshot_support: mount_snapshot_support
   - revert_to_snapshot_support: revert_to_snapshot_support
   - share_type_access:is_public: share_type_access:is_public
   - create_share_from_snapshot_support: create_share_from_snapshot_support
   - description: share_type_description

Response example
----------------

.. literalinclude:: samples/share-types-list-response.json
   :language: javascript


List default share types
========================

.. rest_method::  GET /v2/{tenant_id}/types/default

Lists default share types.

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

   - id: share_type_id_body
   - required_extra_specs: required_extra_specs
   - extra_specs: extra_specs
   - driver_handles_share_servers: driver_handles_share_servers
   - snapshot_support: snapshot_support_1
   - share_type_access:is_public: share_type_access:is_public
   - name: share_type_name
   - description: share_type_description

Response example
----------------

.. literalinclude:: samples/share-types-default-list-response.json
   :language: javascript


Show share type detail
======================

.. rest_method::  GET /v2/{tenant_id}/types/{share_type_id}

Shows details for a specified share type.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id
   - share_type_id: share_type_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_type_id_body
   - required_extra_specs: required_extra_specs
   - extra_specs: extra_specs
   - driver_handles_share_servers: driver_handles_share_servers
   - snapshot_support: snapshot_support_1
   - replication_type: replication_type
   - mount_snapshot_support: mount_snapshot_support
   - revert_to_snapshot_support: revert_to_snapshot_support
   - create_share_from_snapshot_support: create_share_from_snapshot_support
   - share_type_access:is_public: share_type_access:is_public
   - name: share_type_name
   - description: share_type_description

Response Example
----------------

.. literalinclude:: ./samples/share-type-show-response.json
   :language: javascript


List extra specs
================

.. rest_method::  GET /v2/{tenant_id}/types/{share_type_id}/extra_specs

Lists the extra specifications for a share type.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_type_id: share_type_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - extra_specs: extra_specs
   - driver_handles_share_servers: driver_handles_share_servers
   - snapshot_support: snapshot_support_1
   - replication_type: replication_type
   - mount_snapshot_support: mount_snapshot_support
   - revert_to_snapshot_support: revert_to_snapshot_support
   - create_share_from_snapshot_support: create_share_from_snapshot_support

Response example
----------------

.. literalinclude:: samples/share-types-extra-specs-list-response.json
   :language: javascript


Create share type
=================

.. rest_method::  POST /v2/{tenant_id}/types

Creates a share type.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml


   - tenant_id: tenant_id_path
   - extra_specs: extra_specs
   - driver_handles_share_servers: driver_handles_share_servers
   - snapshot_support: snapshot_support_1
   - os-share-type-access:is_public: os-share-type-access:is_public
   - name: share_type_name
   - replication_type: replication_type
   - mount_snapshot_support: mount_snapshot_support
   - revert_to_snapshot_support: revert_to_snapshot_support
   - create_share_from_snapshot_support: create_share_from_snapshot_support
   - description: share_type_description_request

Request example
---------------

.. literalinclude:: samples/share-type-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_type_id_body
   - required_extra_specs: required_extra_specs
   - extra_specs: extra_specs
   - driver_handles_share_servers: driver_handles_share_servers
   - snapshot_support: snapshot_support_1
   - os-share-type-access:is_public: os-share-type-access:is_public
   - share_type_access:is_public: share_type_access:is_public
   - name: share_type_name
   - replication_type: replication_type
   - mount_snapshot_support: mount_snapshot_support
   - revert_to_snapshot_support: revert_to_snapshot_support
   - create_share_from_snapshot_support: create_share_from_snapshot_support
   - description: share_type_description

Response example
----------------

.. literalinclude:: samples/share-type-create-response.json
   :language: javascript


Show share type access details
==============================

.. rest_method::  GET /v2/{tenant_id}/types/{share_type_id}/share_type_access

Shows access details for a share type.

You can view access details for private share types only.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_type_id: share_type_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_9
   - share_type_id: share_type_id_body

Response example
----------------

.. literalinclude:: samples/share-types-list-access-response.json
   :language: javascript


Set extra spec for share type
=============================

.. rest_method::  POST /v2/{tenant_id}/types/{share_type_id}/extra_specs

Sets an extra specification for the share type.

Each driver implementation determines which extra specification
keys it uses. For details, see `Capabilities and Extra-Specs
<https://docs.openstack.org/manila/latest/admin/
capabilities_and_extra_specs.html>`_ and documentation for your driver.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_type_id: share_type_id
   - extra_specs: extra_specs

Request example
---------------

.. literalinclude:: samples/share-type-set-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - extra_specs: extra_specs

Response example
----------------

.. literalinclude:: samples/share-type-set-response.json
   :language: javascript


Unset an extra spec
===================

.. rest_method::  DELETE /v2/{tenant_id}/types/{share_type_id}/extra_specs/{extra-spec-key}

Unsets an extra specification for the share type.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_type_id: share_type_id
   - extra-spec-key: extra-spec-key


Add share type access
=====================

.. rest_method::  POST /v2/{tenant_id}/types/{share_type_id}/action

Adds share type access for a project.

You can add access to private share types only.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_type_id: share_type_id
   - project: project

Request example
---------------

.. literalinclude:: samples/share-type-grant-access-request.json
   :language: javascript


Remove share type access
========================

.. rest_method::  POST /v2/{tenant_id}/types/{share_type_id}/action

Removes share type access from a project.

You can remove access from private share types only.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_type_id: share_type_id
   - project: project

Request example
---------------

.. literalinclude:: samples/share-type-revoke-access-request.json
   :language: javascript


Delete share type
=================

.. rest_method::  DELETE /v2/{tenant_id}/types/{share_type_id}

Deletes a share type.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_type_id: share_type_id
