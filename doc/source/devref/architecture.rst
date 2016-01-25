..
      Copyright 2010-2011 United States Government as represented by the
      Administrator of the National Aeronautics and Space Administration.
      Copyright 2014 Mirantis, Inc.
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

Manila System Architecture
==========================

The Shared File Systems service is intended to be ran on one or more nodes.

Manila uses a sql-based central database that is shared by all manila services in the system.  The amount and depth of the data fits into a sql database quite well.  For small deployments this seems like an optimal solution.  For larger deployments, and especially if security is a concern, manila will be moving towards multiple data stores with some kind of aggregation system.

Components
----------

Below you will a brief explanation of the different components.

::

                                                     /- ( LDAP )
                                 [ Auth Manager ] ---
                                        |            \- ( DB )
                                        |
                                        |

                                        |
 [ Web Dashboard ]- manilaclient -[ manila-api ] -- < AMQP > -- [ manila-scheduler ] -- [ manila-share ] -- ( shared filesystem )
                                        |
                                        |
                                        |
                                        |
                                        |
                                     < REST >


* DB: sql database for data storage. Used by all components (LINKS NOT SHOWN)
* Web Dashboard: external component that talks to the api. Beta extended Horizon available here: https://github.com/NetApp/horizon/tree/manila
* :term:`manila-api`
* Auth Manager: component responsible for users/projects/and roles.  Can backend to DB or LDAP.  This is not a separate binary, but rather a python class that is used by most components in the system.
* :term:`manila-scheduler`
* :term:`manila-share`

Further Challenges
------------------

*   More efficient share/snapshot size calculation
*   Create a notion of "attached" shares with automation of mount operations
*   Support for Nova-network as an alternative to Neutron
*   Support for standalone operation (no dependency on Neutron/Nova-network)
*   Allow admin-created share-servers and share-networks to be used by multiple tenants
*   Support creation of new subnets for share servers (to connect VLANs with VXLAN/GRE/etc)
*   Gateway mediated networking model with NFS-Ganesha
*   Add support for more backends
