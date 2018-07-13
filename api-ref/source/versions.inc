.. -*- rst -*-

============
API versions
============

Lists information for all Shared File Systems API versions.


Concepts
========

In order to bring new features to users over time, the Shared File Systems API
supports versioning. There are two kinds of versions in the Shared File
Systems API:

- ''major versions'', which have dedicated URLs
- ''microversions'', which can be requested through the use of the
  ``X-OpenStack-Manila-API-Version`` header

Read more about microversion guidelines that the service adheres to `here
<https://docs.openstack.org/manila/latest/contributor/api_microversion_dev.html>`_

See `A history of the Shared File Systems API versions
<https://docs.openstack.org/manila/latest/contributor/api_microversion_history.html>`_
to view the evolution of the API and pick an appropriate version for API
requests.


List All Major Versions
=======================

.. rest_method:: GET /

This fetches all the information about all known major API versions in
the deployment. Links to more specific information will be provided
for each API version, as well as information about supported min and
max microversions.

Normal Response Codes: 300

Response
--------

.. rest_parameters:: parameters.yaml

  - versions: versions
  - id: version_id
  - status: version_status
  - links: links
  - media-types: media_types
  - version: version_max
  - min_version: version_min

.. note::

   The ``updated`` and ``media-types`` parameters in the response are
   vestigial and provide no useful information. They will probably be
   deprecated and removed in the future.

Response Example
----------------

This demonstrates the expected response from a bleeding edge server
that supports up to the current microversion. When querying OpenStack
environments you will typically find the current microversion on the
v2.1 API is lower than listed below.

.. literalinclude:: samples/versions-index-response.json
   :language: javascript


Show Details of Specific API Version
====================================

.. rest_method:: GET /{api_version}/

This gets the details of a specific API at it's root. Nearly all this
information exists at the API root, so this is mostly a redundant
operation.

Normal Response Codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - api_version: api_version

Response
--------

.. rest_parameters:: parameters.yaml

  - version: version
  - id: version_id
  - status: version_status
  - links: links
  - version: version_max
  - min_version: version_min
  - media-types: media_types

.. note::

   The ``updated`` and ``media-types`` parameters in the response are
   vestigial and provide no useful information. They will probably be
   deprecated and removed in the future.

Response Example
----------------

This is an example of a ``GET /v2/`` on a relatively current server.

.. literalinclude:: samples/versions-get-version-response.json
   :language: javascript
