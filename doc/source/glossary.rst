========
Glossary
========

.. glossary::

  Manila
   OpenStack project to provide "Shared Filesystems as a service".

  manila-api
   Service that provides a stable RESTful API.
   The service authenticates and routes requests throughout the Shared Filesystem service.
   There is :term:`python-manilaclient` to interact with the API.

  python-manilaclient
   Command line interface to interact with :term:`Manila` via :term:`manila-api` and also a
   Python module to interact programmatically with :term:`Manila`.

  manila-scheduler
   Responsible for scheduling/routing requests to the appropriate :term:`manila-share` service.
   It does that by picking one back-end while filtering all except one back-end.

  manila-share
   Responsible for managing Shared File Service devices, specifically the back-end devices.

  DHSS
   Acronym for 'driver handles share servers'. It defines two different share driver modes
   when they either do handle share servers or not. Each driver is allowed to work only in
   one mode at once. Requirement is to support, at least, one mode.
