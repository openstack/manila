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

Introduction to Manila Shared Filesystem Management Service
===========================================================

Manila is the File Share service project for OpenStack. To administer the
OpenStack File Share service, it is helpful to understand a number of concepts
like share networks, shares, multi-tenancy and back ends that can be configured
with Manila. When configuring the File Share service, it is required to declare
at least one back end. Manila can be configured to run in a single-node
configuration or across multiple nodes. Manila can be configured to provision
shares from one or more back ends.
The OpenStack File Share service allows you to offer file-share services to
users of an OpenStack installation.
