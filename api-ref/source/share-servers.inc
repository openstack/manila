.. -*- rst -*-

Share servers
=============

A share server is created by multi-tenant back-end drivers where
shares are hosted. For example, with the ``generic`` driver, shares
are hosted on Compute VMs.

Administrators can perform read and delete actions for share
servers. An administrator can delete an active share server only if
it contains no dependent shares. If an administrator deletes the
share server, the Shared File Systems service creates a share
server in response to a subsequent create share request.

An administrator can use the ``policy.yaml`` file to grant
permissions for share server actions to other roles.

The status of a share server indicates its current state. After you
successfully set up a share server, its status is ``active``. If
errors occur during set up such as when server data is not valid,
its status is ``error``.

The possible share servers statuses are:

**Share server statuses**

+--------------+------------------------------------------------------------------+
| Status       | Description                                                      |
+--------------+------------------------------------------------------------------+
| ``active``   | Share server was successfully set up.                            |
+--------------+------------------------------------------------------------------+
| ``error``    | The set up or deletion of the share server failed.               |
+--------------+------------------------------------------------------------------+
| ``deleting`` | The share server has no dependent shares and is being deleted.   |
+--------------+------------------------------------------------------------------+
| ``creating`` | The share server is being created on the back end with data from |
|              | the database.                                                    |
+--------------+------------------------------------------------------------------+


List share servers
~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-servers

Lists all share servers.

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

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_server_id
   - project_id: project_id
   - status: status_share_server_body
   - share_network_id: share_network_id_share_servers_response
   - share_network_name: share_network_name
   - host: host_share_server_body
   - updated_at: updated_at
   - share_network_subnet_id: share_network_subnet_id_share_server_body
   - security_service_update_support: share_server_security_service_update_support

Response example
----------------

.. literalinclude:: samples/share-servers-list-response.json
   :language: javascript


Show share server
~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-servers/{share_server_id}

Show a share server's details.

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
  - share_server_id: share_server_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

  - id: share_server_id
  - project_id: project_id
  - status: status_share_server_body
  - backend_details: backend_details
  - share_network_id: share_network_id_share_servers_response
  - share_network_name: share_network_name
  - host: host_share_server_body
  - created_at: created_at
  - updated_at: updated_at
  - identifier: share_server_show_identifier
  - is_auto_deletable: share_server_show_is_auto_deletable
  - share_network_subnet_id: share_network_subnet_id_share_server_body
  - security_service_update_support: security_service_update_support

Response example
----------------

.. literalinclude:: samples/share-server-show-response.json
  :language: javascript


Show share server back end details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-servers/{share_server_id}/details

Shows back end details of a share server.

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
   - share_server_id: share_server_id

Response parameters
-------------------

Response parameters can differ based on the back end used.
Each back end can store any key-value information that it requires.
For example, the generic back end driver might store the router ID.

Response example
----------------

.. literalinclude:: samples/share-server-show-details-response.json
   :language: javascript


Delete share server
~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-servers/{share_server_id}

Deletes a share server.

An administrator can delete an active share server only if it
contains no dependent shares.

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
   - share_server_id: share_server_id


Manage share server (since API v2.49)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method:: POST /v2/share-servers/manage

.. versionadded:: 2.49

Manages a share server

An administrator can bring a pre-existing share server if the back end driver
is operating in ``driver_handles_share_servers=True`` mode.

Response codes
--------------

.. rest_status_code:: success status.yaml

    - 202

.. rest_status_code:: error status.yaml

    - 400
    - 403
    - 422

Request
-------

.. rest_parameters:: parameters.yaml

    - project_id: project_id_path
    - host: manage_host
    - identifier: identifier
    - share_network: share_network_id_manage_server_request
    - driver_options: driver_options
    - share_network_subnet_id: share_network_subnet_id_manage_server_request

Request example
---------------

.. literalinclude:: samples/share-server-manage-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

    - id: share_server_id
    - project_id: project_id
    - updated_at: updated_at
    - status: share_server_status
    - host: manage_host
    - share_network_name: share_network_name
    - share_network_id: share_network_id_share_servers_response
    - created_at: created_at
    - backend_details: backend_details
    - is_auto_deletable: is_auto_deletable
    - identifier: identifier
    - share_network_subnet_id: share_network_subnet_id_manage_server_body
    - security_service_update_support: security_service_update_support


Response examples
-----------------

.. literalinclude:: samples/share-server-manage-response.json
   :language: javascript


Unmanage share server (since API v2.49)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method:: POST /v2/share-servers/{share_server_id}/action

.. versionadded:: 2.49

Unmanages a share server

An administrator can remove a share server from the Shared File System
service's management if there are no associated shares that the service is
aware of. The share server will not be torn down in the back end.

Preconditions

- Share server status must be either ``error``, ``manage_error``, ``active`` or
  ``unmanage_error``.

Response codes
--------------

.. rest_status_code:: success status.yaml

    - 202

.. rest_status_code:: error status.yaml

    - 400
    - 404

Request parameters
------------------

.. rest_parameters:: parameters.yaml

    - project_id: project_id_path
    - share_server_id: share_server_id
    - force: force
    - unmanage: share_server_unmanage

Request example
---------------

.. literalinclude:: samples/share-server-unmanage-request.json
  :language: javascript

Response parameters
-------------------

There is no body content for the response.


Reset status (since API v2.49)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method:: POST /v2/share-servers/{share_server_id}/action

.. versionadded:: 2.49

Resets a share server status

Administrator only. Explicitly updates the state of a share server.

Use the ``policy.yaml`` file to grant permissions for this action to other
roles.

Response codes
--------------

.. rest_status_code:: success status.yaml

    - 202

.. rest_status_code:: error status.yaml

    - 400
    - 404

Request parameters
------------------

.. rest_parameters:: parameters.yaml

    - project_id: project_id_path
    - share_server_id: share_server_id
    - status: share_server_status

Request example
---------------

.. literalinclude:: samples/share-server-reset-state-request.json
   :language: javascript

Response parameters
-------------------

There is no body content for the response.
