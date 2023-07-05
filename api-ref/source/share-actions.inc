.. -*- rst -*-

.. _get-access-rules-before-2-45:

Share actions
=============

Share actions include granting or revoking share access, listing the
available access rules for a share, explicitly updating the state of a
share, resizing a share and un-managing a share.

As administrator, you can reset the state of a share and force-
delete a share in any state. Use the ``policy.yaml`` file to grant
permissions for this action to other roles.

You can set the state of a share to one of these supported states:

- ``available``

- ``error``

- ``creating``

- ``deleting``

- ``error_deleting``

If API version 1.0-2.6 is used then all share actions, defined
below, should include prefix ``os-`` in top element of request
JSON's body.

For example: {"access_list": null} is valid for v2.7+. And {"os-
access_list": null} is valid for v1.0-2.6


Grant access
~~~~~~~~~~~~

All manila shares begin with no access. Clients must be provided with
explicit access via this API.

To grant access, specify one of these supported share access levels:

- ``rw``. Read and write (RW) access.

- ``ro``. Read-only (RO) access.

You must also specify one of these supported authentication
methods:

- ``ip``. Authenticates an instance through its IP address.
  The value specified should be a valid IPv4 or an IPv6 address,
  or a subnet in CIDR notation.
  A valid format is ``X:X:X:X:X:X:X:X``, ``X:X:X:X:X:X:X:X/XX``,
  ``XX.XX.XX.XX``, or ``XX.XX.XX.XX/XX``, etc. For
  example ``0.0.0.0/0`` or ``::/0``.

.. important::

  IPv6 based access is only supported with API version 2.38 and beyond.

.. note::
  Starting from API version 2.82, it is possible to lock the deletion,
  restrict the visibility of sensible fields of the access rules, and specify a
  reason for such locks while invoking the grant access API through the
  parameters ``lock_deletion``, ``lock_visibility`` and ``lock_reason``
  respectively.

- ``cert``. Authenticates an instance through a TLS certificate.
  Specify the TLS identity as the IDENTKEY. A valid value is any
  string up to 64 characters long in the common name (CN) of the
  certificate. The meaning of a string depends on its
  interpretation.

- ``user``. Authenticates by a user or group name. A valid value is
  an alphanumeric string that can contain some special characters
  and is from 4 to 255 characters long.

.. rest_method::  POST /v2/shares/{share_id}/action

Grants access to a share.

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
   - share_id: share_id
   - allow_access: allow_access
   - access_level: access_level
   - access_type: access_type
   - access_to: access_to
   - metadata: access_metadata_grant_access
   - lock_visibility: lock_visibility
   - lock_deletion: lock_deletion
   - lock_reason: resource_lock_lock_reason

Request example
---------------

.. literalinclude:: samples/share-actions-grant-access-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_id: access_share_id
   - created_at: created_at
   - updated_at: updated_at
   - access_type: access_type
   - access_to: access_to
   - access_key: access_key
   - access: access
   - access_level: access_level
   - id: access_rule_id
   - metadata: access_metadata

Response example
----------------

.. literalinclude:: samples/share-actions-grant-access-response.json
   :language: javascript


Revoke access
~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

The shared file systems service stores each access rule in its database and
assigns it a unique ID. This ID can be used to revoke access after access
has been requested.

.. note::
  In case the access rule had its deletion locked, it will be necessary to
  provide the ``unrestrict`` parameter in the revoke access request.

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
   - share_id: share_id
   - deny_access: deny_access
   - access_id: access_id
   - unrestrict: unrestrict_access


Request example
---------------

.. literalinclude:: samples/share-actions-revoke-access-request.json
   :language: javascript


List access rules (DEPRECATED)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::

   This API is deprecated starting with microversion 2.45 and requests to
   this API will fail with a 404 starting from microversion 2.45. Use
   :ref:`List share access rules <get-access-rules-after-2-45>` API
   instead of this API from version 2.45.

.. rest_method::  POST /v2/shares/{share_id}/action

Lists access rules for a share. The Access ID returned is necessary to deny
access.

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
   - share_id: share_id
   - access_list: access_list


Request example
---------------

.. literalinclude:: samples/share-actions-list-access-rules-request.json
   :language: javascript


Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - access_type: access_type
   - access_key: access_key
   - access_to: access_to
   - access_level: access_level
   - state: state
   - access_list: access_list
   - id: access_rule_id
   - created_at: created_at
   - updated_at: updated_at

Response example
----------------

.. literalinclude:: samples/share-actions-list-access-rules-response.json
   :language: javascript


Reset share state
~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

Administrator only. Explicitly updates the state of a share.

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
   - share_id: share_id
   - reset_status: reset_status
   - status: share_status_request


Request example
---------------

.. literalinclude:: samples/share-actions-reset-state-request.json
   :language: javascript


Force-delete share
~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

Administrator only. Force-deletes a share in any state.

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
   - share_id: share_id
   - force_delete: share_force_delete

Request example
---------------

.. literalinclude:: samples/share-actions-force-delete-request.json
   :language: javascript


Extend share
~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

Increases the size of a share.

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
   - share_id: share_id
   - extend: extend
   - new_size: share_new_size
   - force: share_force_extend


Request example
---------------

.. literalinclude:: samples/share-actions-extend-request.json
   :language: javascript


Shrink share
~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

Shrinks the size of a share.

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
   - share_id: share_id
   - shrink: shrink
   - new_size: share_new_size

Request example
---------------

.. literalinclude:: samples/share-actions-shrink-request.json
   :language: javascript


Unmanage share (since API v2.7)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

.. versionadded:: 2.7


Use this API to remove a share from the management of the Shared File
Systems service without deleting the share.

Administrator only. Use the ``policy.yaml`` file to grant permissions for this
action to other roles.


Preconditions:

- You should remove any snapshots and share replicas before attempting to
  unmanage a share.

.. note::

   Unmanaging shares that are created on top of share servers (i.e. created
   with share networks) is not supported prior to API version 2.49.

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
   - share_id: share_id
   - unmanage: share_unmanage

Request example
---------------

.. literalinclude:: samples/share-actions-unmanage-request.json
   :language: javascript


Response parameters
-------------------
There is no body content for the response.


Revert share to snapshot (since API v2.27)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

.. versionadded:: 2.27

Reverts a share to the specified snapshot, which must be the most recent one
known to manila.

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
   - share_id: share_id
   - snapshot_id: snapshot_id


Request example
---------------

.. literalinclude:: samples/share-actions-revert-to-snapshot-request.json
   :language: javascript


Soft delete share (since API v2.69)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

.. versionadded:: 2.69

Soft delete a share to recycle bin.

Preconditions

- Share status must be ``available``, ``error`` or ``inactive``

- Share can't have any snapshot.

- Share can't have a share group snapshot.

- Share can't have dependent replicas.

- You cannot soft delete share that already is in the Recycle Bin..

- You cannot soft delete a share that doesn't belong to your project.

- You cannot soft delete a share is busy with an active task.

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
   - share_id: share_id


Request example
---------------

.. literalinclude:: samples/share-actions-soft-delete-request.json
   :language: javascript


Restore share (since API v2.69)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

.. versionadded:: 2.69

Restore a share from recycle bin.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id


Request example
---------------

.. literalinclude:: samples/share-actions-restore-request.json
   :language: javascript
