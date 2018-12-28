..
      Copyright 2010-2011 OpenStack LLC
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Adding a Method to the OpenStack Manila API
===========================================

The interface to manila is a RESTful API. REST stands for Representational
State Transfer and provides an architecture "style" for distributed systems
using HTTP for transport. Figure out a way to express your request and
response in terms of resources that are being created, modified, read, or
destroyed. Manila's API aims to conform to the `guidelines <http://specs
.openstack.org/openstack/api-sig/>`_ set by OpenStack API SIG.

Routing
-------

To map URLs to controllers+actions, manila uses the Routes package. See
the `routes package documentation <https://routes.readthedocs.io/en/latest/>`_
for more information.

URLs are mapped to "action" methods on "controller" classes in
``manila/api/<VERSION>/router.py``.

These are two methods of the routes package that are used to perform the
mapping and the routing:

- mapper.connect() lets you map a single URL to a single action on a
  controller.
- mapper.resource() connects many standard URLs to actions on a controller.

Controllers and actions
-----------------------

Controllers live in ``manila/api/v1`` and ``manila/api/v2``.

See ``manila/api/v1/shares.py`` for an example.

Action methods take parameters that are sucked out of the URL by
mapper.connect() or .resource().  The first two parameters are self and the
WebOb request, from which you can get the req.environ, req.body,
req.headers, etc.

Actions return a dictionary, and wsgi.Controller serializes that to JSON.

Faults
------

If you need to return a non-200, you should return faults.Fault(webob.exc
.HTTPNotFound()) replacing the exception as appropriate.

Evolving the API
----------------

The ``v1`` version of the manila API has been deprecated. The ``v2`` version
of the API supports micro versions. So all changes to the v2 API strive to
maintain stability at any given API micro version, so consumers can safely
rely on a specific micro version of the API never to change the request and
response semantics. Read more about :doc:`API Microversions
<api_microversion_dev>` to understand how stability and backwards
compatibility are maintained.
