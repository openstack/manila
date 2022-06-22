.. -*- rst -*-

Manage and unmanage shares (DEPRECATED)
=======================================

Allows bringing shared file systems under service management.


Manage share (DEPRECATED)
~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::

   This API is deprecated starting with microversion 2.7 and requests to
   this API will fail with a 404 starting from microversion 2.7. Use
   `Share Manage API <#manage-share-since-api-v2-7>`_ instead of this API
   from version 2.7.

.. rest_method::  POST /v2/os-share-manage

Use this API to bring a share under the management of the Shared File
Systems service. In the service, the share will be represented as a resource
in the database. It can have a user defined name and description.

Administrator only. Use the ``policy.yaml`` file to grant permissions for this
action to other roles.

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
   - share: share
   - protocol: protocol
   - name: name_request
   - display_name: display_name_request
   - share_type: share_type_request
   - driver_options: driver_options
   - export_path: export_path
   - service_host: service_host
   - description: description_request
   - display_description: display_description_request

Request example
---------------

.. literalinclude:: samples/share-manage-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share: share
   - links: links
   - availability_zone: availability_zone
   - share_network_id: share_network_id
   - export_locations: export_locations
   - share_server_id: share_server_id
   - snapshot_id: snapshot_id_shares_response
   - id: share_id_response
   - size: size_response
   - share_type: share_type_shares_response
   - share_type_name: share_type_name
   - export_location: export_location
   - project_id: project_id
   - metadata: metadata
   - status: share_status_response
   - description: description
   - host: host_resource_response
   - is_public: is_public_shares_response
   - snapshot_support: snapshot_support
   - name: name
   - created_at: created_at
   - share_proto: share_proto

Response example
----------------

.. literalinclude:: samples/share-manage-response.json
   :language: javascript


Unmanage share (DEPRECATED)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::

   This API is deprecated starting with microversion 2.7 and requests to
   this API will fail with a 404 starting from microversion 2.7. Use
   `Share Unmanage API <#unmanage-share-since-api-v2-7>`_ instead of this
   API from version 2.7.

.. rest_method::  POST /v2/os-share-unmanage/{share_id}/unmanage

Use this API to remove a share from the management of the Shared File
Systems service without deleting the share.

Administrator only. Use the ``policy.yaml`` file to grant permissions for this
action to other roles.


Preconditions:

- This API does not support unmanaging shares that are created on top
  of share servers (i.e. created with share networks).
- You should remove any snapshots and share replicas before attempting to
  unmanage a share.


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


Response parameters
-------------------

There is no body content for the response.
