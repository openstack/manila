.. _share-node-install:

Install and configure a share node
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure a share node for the
Shared File Systems service.

.. note::

   The manila-share process can run in two modes, with and without handling of
   share servers. Some drivers may support either modes; while some may only
   support one of the two modes. See the `Configuration Reference
   <https://docs.openstack.org/manila/latest/configuration/shared-file-systems/overview.html>`_
   to determine if the driver you choose supports the driver mode desired.
   This tutorial describes setting up each driver mode using an example driver
   for the mode.

Note that installation and configuration vary by distribution.

.. toctree::
   :maxdepth: 1

   install-share-obs.rst
   install-share-rdo.rst
   install-share-ubuntu.rst
   install-share-debian.rst
