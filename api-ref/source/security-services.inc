.. -*- rst -*-

=================
Security services
=================

You can create, update, view, and delete a security service. A
security service stores configuration information for clients for
authentication and authorization (AuthN/AuthZ). For example, a
share server will be the client for an existing service such as
LDAP, Kerberos, or Microsoft Active Directory.

You can associate a share with from one to three security service
types:

- ``ldap``. LDAP.

- ``kerberos``. Kerberos.

- ``active_directory``. Microsoft Active Directory.

You can configure a security service with these options:

- A DNS IP address.

- An IP address or host name.

- A domain.

- A user or group name.

- The password for the user, if you specify a user name.


List security services
======================

.. rest_method::  GET /v2/{tenant_id}/security-services

Lists all security services.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: status_2
   - type: type
   - id: id_3
   - name: name_12

Response example
----------------

.. literalinclude:: samples/security-services-list-response.json
   :language: javascript


List security services with details
===================================

.. rest_method::  GET /v2/{tenant_id}/security-services/detail

Lists all security services with details.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: status_2
   - id: id_3
   - project_id: project_id_3
   - type: type
   - name: name_12
   - description: description_12
   - dns_ip: dns_ip
   - user: user
   - password: password
   - domain: domain
   - server: server
   - updated_at: created_at_3
   - created_at: created_at_1

Response example
----------------

.. literalinclude:: samples/security-services-list-detailed-response.json
   :language: javascript


Show security service details
=============================

.. rest_method::  GET /v2/{tenant_id}/security-services/{security_service_id}

Shows details for a security service.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - security_service_id: security_service_id_1

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: status_2
   - id: id_3
   - project_id: project_id_3
   - type: type
   - name: name_12
   - description: description_12
   - dns_ip: dns_ip
   - user: user
   - password: password
   - domain: domain
   - server: server
   - updated_at: created_at_3
   - created_at: created_at_1

Response example
----------------

.. literalinclude:: samples/security-service-show-response.json
   :language: javascript


Create security service
=======================

.. rest_method::  POST /v2/{tenant_id}/security-services

Creates a security service.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - type: type
   - name: name_12
   - description: description_12
   - dns_ip: dns_ip
   - user: user
   - password: password
   - domain: domain
   - server: server

Request example
---------------

.. literalinclude:: samples/security-service-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: status_2
   - id: id_3
   - project_id: project_id_3
   - type: type
   - name: name_12
   - description: description_12
   - dns_ip: dns_ip
   - user: user
   - password: password
   - domain: domain
   - server: server
   - updated_at: created_at_3
   - created_at: created_at_1

Response example
----------------

.. literalinclude:: samples/security-service-create-response.json
   :language: javascript


Update security service
=======================

.. rest_method::  PUT /v2/{tenant_id}/security-services/{security_service_id}

Updates a security service.

If the security service is in ``active`` state, you can update only
the ``name`` and ``description`` attributes. A security service in
``active`` state is attached to a share network with an associated
share server.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - security_service_id: security_service_id_1
   - type: type
   - name: name_12
   - description: description_12
   - dns_ip: dns_ip
   - user: user
   - password: password
   - domain: domain
   - server: server

Request example
---------------

.. literalinclude:: samples/security-service-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: status_2
   - id: id_3
   - project_id: project_id_3
   - type: type
   - name: name_12
   - description: description_12
   - dns_ip: dns_ip
   - user: user
   - password: password
   - domain: domain
   - server: server
   - updated_at: created_at_3
   - created_at: created_at_1

Response example
----------------

.. literalinclude:: samples/security-service-update-response.json
   :language: javascript


Delete security service
=======================

.. rest_method::  DELETE /v2/{tenant_id}/security-services/{security_service_id}

Deletes a security service.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - security_service_id: security_service_id_1
