.. -*- rst -*-

Share group types (since API v2.31)
===================================

A share group type enables you to filter or choose back ends before you
create a share group.

You can set share group types as either public or private. By default a
share group type is created as publicly accessible. Set
``share_group_type_access:is_public`` to ``False`` to make a share group
type private.

You can manage access to the private share group types for different
projects. You can add access, remove access, and get information about
access for a private share group type.

Administrators can specify which `share type(s) <#experimental-apis>`_
a given group type may contain. If Administrators do not explicitly
associate share types with a given share group type, the service will associate
the share type configured as the ``default_share_type`` with the share group
type. When creating a share group, the scheduler picks one of the
back ends that match a combination of the extra specs in the specified share
type(s) and share group type.

Administrators can also set additional group extra specifications for a
share group type for the following purposes:

- Filter back ends by group scheduler. Specify these group extras specifications
  in this format: ``group_specs=value``. For example,
  ``consistent_snapshot_support=true``.

.. note::

    Share Group Type APIs are no longer considered experimental since API
    version 2.55.

List share group types
~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-group-types

.. versionadded:: 2.31

Lists all share group types.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - is_public: is_public_query
   - group_specs: group_specs_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_type_id_required
   - is_public: share_group_type_is_public
   - share_types: share_types_1
   - name: share_group_type_name
   - group_specs: group_specs_required
   - is_default: is_group_type_default

Response example
----------------

.. literalinclude:: samples/share-group-types-list-response.json
   :language: javascript


List default share group types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-group-types/default

.. versionadded:: 2.31

Lists default share group types.

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

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_group_type_id_required
   - is_public: share_group_type_is_public
   - share_types: share_types_1
   - name: share_group_type_name
   - group_specs: group_specs_required
   - is_default: is_group_type_default

Response example
----------------

.. literalinclude:: samples/share-group-types-default-list-response.json
   :language: javascript


List share group types extra specs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-group-types/{share_group_type_id}/group-specs

.. versionadded:: 2.31

Lists the extra specifications for a share group type.

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
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-group-types

.. versionadded:: 2.31

Creates a share group type.

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

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_types: share_types_1
   - name: share_group_type_name_request
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
   - is_default: is_group_type_default

Response example
----------------

.. literalinclude:: samples/share-group-type-create-response.json
   :language: javascript


Show share group type access details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-group-types/{share_group_type_id}/access

.. versionadded:: 2.31

Shows access details for a share group type.

You can view access details for private share group types only.

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
   - share_group_type_id: share_group_type_id_required

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_group_type_id: share_group_type_id_required
   - project_id: project_id_type_access

Response example
----------------

.. literalinclude:: samples/share-group-types-list-access-response.json
   :language: javascript


Set extra spec for share group type
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-group-types/{share_group_type_id}/group-specs

.. versionadded:: 2.31

Sets an extra specification for the share group type.

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

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
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
~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-group-types/{share_group_type_id}/group-specs/{group_spec_key}

.. versionadded:: 2.31

Unsets an extra specification for the share type.

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
   - share_group_type_id: share_group_type_id_required
   - group_spec_key: group_spec_key


Add share group type access
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-group-types/{share_group_type_id}/action

.. versionadded:: 2.31

Adds share group type access for a project.

You can add access to private share group types only.

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
   - share_group_type_id: share_group_type_id_path
   - addProjectAccess: add_project_access
   - project: project_id_type_access_grant_request

Request example
---------------

.. literalinclude:: samples/share-group-type-grant-access-request.json
   :language: javascript


Remove share group type access
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-group-types/{share_group_type_id}/action

.. versionadded:: 2.31

Removes share group type access from a project.

You can remove access from private share group types only.

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
   - share_group_type_id: share_group_type_id_path
   - removeProjectAccess: remove_project_access
   - project: project_id_type_access_revoke_request


Request example
---------------

.. literalinclude:: samples/share-group-type-revoke-access-request.json
   :language: javascript


Delete share group type
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-group-types/{share_group_type_id}

.. versionadded:: 2.31

Deletes a share group type.

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
   - share_group_type_id: share_group_type_id_path
