.. -*- rst -*-

QoS types
=========

A qos-type provides information to backend storage drivers for implementing
quality of service(QoS) on resources like shares or share-servers. It contains
specifications that act as parameters needed to define QoS policies.

Administrators can create qos-type along-with specs. These two, in combination
will represent QoS policy. All users within the cloud can then access QoS types.

When you create a QoS Type, you can submit a request body with a ``qos_type``
object. In order to create a share with particular QoS type, the user needs to
select a valid share-type having reference of QoS type. The share-type extra
specification called ``default_qos_type`` should have value as a name of
``qos_type`` object.

The scheduler uses the special ``capabilities`` prefix for
filtering. The scheduler can only create a share on a back end that
reports capabilities that match the un-scoped extra-spec keys for
the share type. For details, see `Capabilities and Extra-Specs
<https://docs.openstack.org/manila/latest/admin/
capabilities_and_extra_specs.html>`_. In case of qos-type, the capability
would be ``default_qos_type``.


List QoS types
~~~~~~~~~~~~~~

.. rest_method::  GET /v2/qos-types

Lists all QoS types.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: qos_type_id_body
   - name: qos_type_name
   - description: qos_type_description
   - specs: qos_type_specs

Response example
----------------

.. literalinclude:: samples/qos-types-list-response.json
   :language: javascript


Show QoS type detail
~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/qos-types/{qos_type_id}

Shows details for a specified QoS type.

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

   - qos_type_id: qos_type_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: qos_type_id_body
   - name: qos_type_name
   - description: qos_type_description
   - specs: qos_type_specs

Response Example
----------------

.. literalinclude:: ./samples/qos-type-show-response.json
   :language: javascript


List specs
~~~~~~~~~~

.. rest_method::  GET /v2/qos-types/{qos_type_id}/specs

Lists the specifications for a QoS type.

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

   - qos_type_id: qos_type_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - specs: qos_type_specs

Response example
----------------

.. literalinclude:: samples/qos-types-specs-list-response.json
   :language: javascript


Create QoS type
~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/qos-types

Creates a QoS type.

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

   - name: qos_type_name_request
   - description: qos_type_description_request
   - specs: qos_type_specs_request_body

Request example
---------------

.. literalinclude:: samples/qos-type-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: qos_type_id_body
   - name: qos_type_name
   - description: qos_type_description
   - specs: qos_type_specs

Response example
----------------

.. literalinclude:: samples/qos-type-create-response.json
   :language: javascript


Set spec for QoS type
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/qos-types/{qos_type_id}/specs

Sets a specification for the QoS type.

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

   - qos_type_id: qos_type_id_path
   - specs: qos_type_specs_request_body

Request example
---------------

.. literalinclude:: samples/qos-type-set-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - specs: qos_type_specs

Response example
----------------

.. literalinclude:: samples/qos-type-set-response.json
   :language: javascript


Unset an extra spec
~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/qos-types/{qos_type_id}/specs/{spec-key}

Unsets an specification for the QoS type.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - qos_type_id: qos_type_id_path
   - spec-key: qos_type_spec_key_path


Delete QoS type
~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/qos-types/{qos_type_id}

Deletes a QoS type.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - qos_type_id: qos_type_id_path


Update QoS type
~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/qos-types/{qos_type_id}

Update a QoS type. QoS type specs cannot be updated
with this API.

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

   - qos_type_id: qos_type_id_path
   - description: qos_type_description_update_request

Request example
---------------

.. literalinclude:: samples/qos-type-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: qos_type_id_body
   - name: qos_type_name
   - description: qos_type_description
   - specs: qos_type_specs

Response example
----------------

.. literalinclude:: samples/qos-type-update-response.json
   :language: javascript
