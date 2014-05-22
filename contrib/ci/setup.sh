#!/bin/bash
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This script is executed before of all exports of env vars in devstack gate.

export PYTHONUNBUFFERED=true
export DEVSTACK_GATE_TIMEOUT=60
export ENABLED_SERVICES=manila,m-api,m-shr,m-sch,tempest
export PROJECTS="stackforge/manila $PROJECTS"
export PROJECTS="stackforge/python-manilaclient $PROJECTS"
export DEVSTACK_GATE_TEMPEST_ALLOW_TENANT_ISOLATION=1
export DEVSTACK_GATE_NEUTRON=1
export TEMPEST_CONCURRENCY=2
export KEEP_LOCALRC=1
export MANILA_TESTS='tempest.cli.*manila*'
if [[ ! "$ZUUL_PROJECT" =~ python-manilaclient ]]; then
    MANILA_TESTS+=' tempest.api.share*';
fi
export TEMPEST_SERVICES+=,manila

export MANILA_MULTI_BACKEND=False
export MANILA_BACKEND1_CONFIG_GROUP_NAME=london
export MANILA_SHARE_BACKEND1_NAME=LONDON
export MANILA_BACKEND2_CONFIG_GROUP_NAME=paris
export MANILA_SHARE_BACKEND2_NAME=PARIS

export API_RATE_LIMIT=False
export SHARE_BACKING_FILE_SIZE=30G
export VOLUME_BACKING_FILE_SIZE=30G
