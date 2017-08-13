.. _manila-controller:

Install and configure controller node
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure the Shared File Systems
service, code-named manila, on the controller node. This service requires at
least one additional share node that manages file storage back ends.

This section assumes that you already have a working OpenStack
environment with at least the following components installed:
Compute, Image Service, Identity.

Note that installation and configuration vary by distribution.

.. toctree::
   :maxdepth: 1

   install-controller-obs.rst
   install-controller-rdo.rst
   install-controller-ubuntu.rst
   install-controller-debian.rst
