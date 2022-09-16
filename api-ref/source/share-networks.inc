.. -*- rst -*-

Share networks
==============

A share network resource stores network information to create and manage
share servers. Shares created with share networks are exported on these
networks with the help of share servers.

You can create, update, view, and delete a share network.

When you create a share network, you may optionally specify an associated
neutron network and subnetwork.

For more information about supported plug-ins for share networks,
see `Manila Network Plugins <https://docs.openstack.org/manila/latest/
admin/shared-file-systems-network-plugins.html>`_.

A share network resource has these attributes:

- The IP block in Classless Inter-Domain Routing (CIDR) notation
  from which to allocate the network.

- The IP version of the network.

- The network type, which is ``vlan``, ``vxlan``, ``gre``, or
  ``flat``.

- If the network uses segmentation, a segmentation identifier. For
  example, VLAN, VXLAN, and GRE networks use segmentation.

A share network resource can also have a user defined name and description.

.. note::
   Since API version 2.51, a share network is allowed to span multiple subnets
   and the fields ``neutron_net_id``, ``neutron_subnet_id``, ``network_type``,
   ``cidr``, ``ip_version``, ``gateway``, ``segmentation_id`` and ``mtu`` were
   moved from the share network to the subnet. The share network subnet also
   contains a an attribute called ``availability_zone``.


List share networks
~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-networks

Lists all share networks.


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
   - name~: name_inexact_query
   - description~: description_inexact_query
   - name: name_query
   - description: description_query
   - created_since: created_since_query
   - created_before: created_before_query
   - security_service_id: security_service_query
   - nova_net_id: nova_net_id_query
   - neutron_net_id: neutron_net_id_query
   - neutron_subnet_id: neutron_subnet_id_query
   - network_type: network_type_query
   - segmentation_id: segmentation_id_query
   - cidr: cidr_query
   - ip_version: ip_version_query
   - offset: offset
   - limit: limit

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id_share_networks_response
   - name: name

Response example
----------------

.. literalinclude:: samples/share-networks-list-response.json
   :language: javascript


List share networks with details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-networks/detail

Lists all share networks with details.


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
   - name~: name_inexact_query
   - description~: description_inexact_query
   - created_since: created_since_query
   - created_before: created_before_query
   - nova_net_id: nova_net_id_query
   - neutron_net_id: neutron_net_id_query
   - neutron_subnet_id: neutron_subnet_id_query
   - network_type: network_type_query
   - segmentation_id: segmentation_id_query
   - cidr: cidr_query
   - ip_version: ip_version_query
   - offset: offset
   - limit: limit
   - security_service_id: security_service_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id_share_networks_response
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - gateway: share_network_gateway
   - mtu: share_network_mtu
   - share_network_subnets: share_network_share_network_subnets
   - security_service_update_support: share_network_security_service_update_support
   - status: share_network_status

Response example
----------------

.. literalinclude:: samples/share-networks-list-detailed-response.json
   :language: javascript

.. include:: common/share-network-span-multiple-subnets-note.rst

.. literalinclude:: samples/share-networks-list-detailed-response-with-subnets.json
   :language: javascript


Show share network details
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-networks/{share_network_id}

Shows details for a share network.

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
   - share_network_id: share_network_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id_share_networks_response
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - gateway: share_network_gateway
   - mtu: share_network_mtu
   - share_network_subnets: share_network_share_network_subnets
   - security_service_update_support: share_network_security_service_update_support
   - status: share_network_status

Response example
----------------

.. literalinclude:: samples/share-network-show-response.json
   :language: javascript

.. include:: common/share-network-span-multiple-subnets-note.rst

.. literalinclude:: samples/share-network-show-response-with-subnets.json
   :language: javascript


Create share network
~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-networks

Creates a share network.


Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 413
   - 422
   - 500

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - neutron_net_id: neutron_net_id_request
   - neutron_subnet_id: neutron_subnet_id_request
   - name: name_request
   - description: description_request
   - availability_zone: share_network_availability_zone_request

Request example
---------------

.. literalinclude:: samples/share-network-create-request.json
   :language: javascript

.. note::
   Since API version 2.51, an ``availability_zone`` can be specified with the
   share network creation request. In case you do not specify an avaiability
   zone, this field will be set to null and the subnet created will be
   considered a ``default`` subnet by the Shared File Systems service. You can
   have only one default subnet per share network. If you attempt to create
   another default subnet in a share network that already has a default one,
   the Shared File Systems Service will deny the operation.

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id_share_networks_response
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - gateway: share_network_gateway
   - mtu: share_network_mtu
   - share_network_subnets: share_network_share_network_subnets
   - security_service_update_support: share_network_security_service_update_support
   - status: share_network_status

Response example
----------------

.. literalinclude:: samples/share-network-create-response.json
   :language: javascript

.. note::
   Since API version 2.51, share networks are able to span multiple subnets, so
   when creating a share network, a new subnet will automatically be created by
   the Shared File Systems service and attached into the share network.

.. literalinclude:: samples/share-network-create-response-with-subnets.json
   :language: javascript


Add security service to share network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-networks/{share_network_id}/action

Adds a security service to a share network.

.. note::
    As of API version 2.63, manila allows adding security services to share
    networks that are being used if supported by the share backends. Before
    requesting to add a security service to a share network that is in use,
    make sure to use the `check add API
    <https://docs.openstack.org/api-ref/shared-file-system/#check-share-network-security-service-add-since-api-v2-63>`_.

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

   - project_id: project_id
   - share_network_id: share_network_id_path
   - security_service_id: security_service_id

Request example
---------------

.. literalinclude:: samples/share-network-add-security-service-request.json
   :language: javascript


Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id_share_networks_response
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - gateway: share_network_gateway
   - mtu: share_network_mtu
   - share_network_subnets: share_network_share_network_subnets
   - security_service_update_support: share_network_security_service_update_support
   - status: share_network_status

Response example
----------------

.. literalinclude:: samples/share-network-add-security-service-response.json
   :language: javascript

.. include:: common/share-network-span-multiple-subnets-note.rst

.. literalinclude:: samples/share-network-add-security-service-response-with-subnets.json
   :language: javascript


Remove security service from share network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-networks/{share_network_id}/action

Removes a security service from a share network.


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
   - share_network_id: share_network_id_path
   - security_service_id: share_network_security_service_id

Request example
---------------

.. literalinclude:: samples/share-network-remove-security-service-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id_share_networks_response
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - gateway: share_network_gateway
   - mtu: share_network_mtu
   - security_service_update_support: share_network_security_service_update_support
   - status: share_network_status

Response example
----------------

.. literalinclude:: samples/share-network-remove-security-service-response.json
   :language: javascript

.. include:: common/share-network-span-multiple-subnets-note.rst

.. literalinclude:: samples/share-network-remove-security-service-response-with-subnets.json
   :language: javascript


Update share network
~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/share-networks/{share_network_id}

Updates a share network.

Note that if the share network is used by any share server, you can
update only the ``name`` and ``description`` attributes.

.. note::
   Since API version 2.51, can only able to update the ``neutron_net_id``
   and ``neutron_subnet_id`` of the default subnet.

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
   - share_network_id: share_network_id_path
   - name: name_request
   - description: description_request
   - neutron_net_id: neutron_net_id_request
   - neutron_subnet_id: neutron_subnet_id_request

Request example
---------------

.. literalinclude:: samples/share-network-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id_share_networks_response
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - gateway: share_network_gateway
   - mtu: share_network_mtu
   - security_service_update_support: share_network_security_service_update_support
   - status: share_network_status

Response example
----------------

.. literalinclude:: samples/share-network-update-response.json
   :language: javascript

.. include:: common/share-network-span-multiple-subnets-note.rst

.. literalinclude:: samples/share-network-update-response-with-subnets.json
   :language: javascript


Delete share network
~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-networks/{share_network_id}

Deletes a share network.

Preconditions

- You cannot delete a share network if it has shares created/exported on it.

- You cannot delete a share network if it has share groups created on it.

- You cannot delete a share network if it has more than one share network
  subnet on it (since API version 2.51).

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
   - share_network_id: share_network_id_path


Update share network security service (since API v2.63)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-networks/{share_network_id}/action

.. versionadded:: 2.63

Replaces a security service in a share network. Both current and the new
security service must have the same type and must have the
``security_service_update_support`` capability set to ``True``.

.. important::
    Before calling the update share network security service API, make sure
    to check if the share backends within the share network can hold the
    operation, through the `check update API
    <https://docs.openstack.org/api-ref/shared-file-system/#check-share-network-security-service-update-since-api-v2-63>`_.

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
   - share_network_id: share_network_id_path
   - current_security_service: current_share_network_security_service_id
   - new_security_service: new_share_network_security_service_id

Request example
---------------

.. literalinclude:: samples/share-network-update-security-service-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - gateway: share_network_gateway
   - mtu: share_network_mtu
   - share_network_subnets: share_network_share_network_subnets
   - security_service_update_support: share_network_security_service_update_support
   - status: share_network_status

Response example
----------------

.. literalinclude:: samples/share-network-update-security-service-response.json
   :language: javascript


.. _share-net-sec-service-update-check:

Check share network security service update (since API v2.63)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-networks/{share_network_id}/action

.. versionadded:: 2.63

Checks if an existing security service can be replaced on a share network that
is in use. This operation must be triggered before an actual request to update
a share network security service is requested.


Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 404
   - 409


Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_network_id: share_network_id_path
   - current_service_id: current_share_network_security_service_id
   - new_service_id: new_share_network_security_service_id
   - reset_operation: reset_operation

Request example
---------------

.. literalinclude:: samples/share-network-update-security-service-check-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - operation: requested_operation_name
   - current_security_service: current_share_network_security_service_id
   - new_security_service: new_share_network_security_service_id
   - compatible: operation_is_compatible
   - requested_operation: requested_check_operation
   - hosts_check_result: hosts_check_result

Response example
----------------

.. literalinclude:: samples/share-network-update-security-service-check-response.json
   :language: javascript


Check share network security service add (since API v2.63)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-networks/{share_network_id}/action

.. versionadded:: 2.63

Checks if a new security service can be added to a share network that's already
in use. This  operation must be triggered before an actual request to add a
security service to an in use share network.


Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 404
   - 409


Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_network_id: share_network_id_path
   - security_service_id: current_share_network_security_service_id
   - reset_operation: reset_operation

Request example
---------------

.. literalinclude:: samples/share-network-add-security-service-check-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - operation: requested_operation_name
   - current_security_service: current_share_network_security_service_id
   - new_security_service: new_share_network_security_service_id
   - compatible: operation_is_compatible
   - requested_operation: requested_operation
   - hosts_check_result: hosts_check_result

Response example
----------------

.. literalinclude:: samples/share-network-add-security-service-check-response.json
   :language: javascript


Reset status (since API v2.63)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method:: POST /v2/share-networks/{share_network_id}/action

.. versionadded:: 2.63

Resets a share network status.

Administrator only. Explicitly updates the state of a share network.

Response codes
--------------

.. rest_status_code:: success status.yaml

    - 202

.. rest_status_code:: error status.yaml

    - 400
    - 401
    - 403
    - 404

Request parameters
------------------

.. rest_parameters:: parameters.yaml

    - project_id: project_id_path
    - share_network_id: share_network_id_path
    - status: share_network_status

Request example
---------------

.. literalinclude:: samples/share-network-reset-state-request.json
   :language: javascript


Response parameters
-------------------

There is no body content for the response.
