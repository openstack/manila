================
Service Overview
================

The OpenStack Shared File Systems service (manila) provides file storage to a
virtual machine. The Shared File Systems service provides an abstraction
for managing and provisioning of file shares. The service also enables
management of share types as well as share snapshots if a driver supports
them.

The Shared File Systems service consists of the following components:

manila-api
  A WSGI app that authenticates and routes requests to the Shared File
  Systems service.

manila-data
  A standalone service whose purpose is to process data operations such as
  copying, share migration or backup.

manila-scheduler
  Schedules and routes requests to the appropriate share service. The
  scheduler uses configurable filters and weighers to route requests. The
  Filter Scheduler is the default and enables filters on various attributes
  of back ends, such as, Capacity, Availability Zone and other capabilities.

manila-share
  Manages back-end devices that provide shared file systems. A manila-share
  service talks to back-end devices by using share back-end drivers as
  interfaces. A share driver may operate in one of two modes, with or
  without handling of share servers. Share servers export file shares
  via share networks. When share servers are not managed by a driver
  within the shared file systems service, networking requirements should
  be handled out of band of the shared file systems service.

Messaging queue
  Routes information between the Shared File Systems processes.

For more information, see `Configuration Reference Guide
<https://docs.openstack.org/manila/latest/configuration/shared-file-systems/overview.html>`_.
