..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Introduction to the Shared File Systems service
===========================================================

Manila is the file share service project for OpenStack. Manila
provides the management of file shares for example, NFS and CIFS as a
core service to OpenStack. Manila works with a variety of proprietary
backend storage arrays and appliances, with open source distributed
filesystems, as well as with a base Linux NFS or Samba
server. There are a number of concepts that will help in better
understanding of the solutions provided by manila. One aspect can be
to explore the different service possibilities provided by manila.

Manila, depending on the driver, requires the user by default to create a
share network using neutron-net-id and neutron-subnet-id (GlusterFS native
driver does not require it). After creation of the share network, the user
can proceed to create the shares. Users in manila can configure multiple
back-ends just like Cinder. Manila has a share server assigned to every
tenant. This is the solution for all back-ends except for GlusterFS. The
customer in this scenario is prompted to create a share server using neutron
net-id and subnet-id before even trying to create a share.

The current low-level services available in manila are:

- :term:`manila-api`

- :term:`manila-scheduler`

- :term:`manila-share`

