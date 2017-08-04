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

Manila share driver hooks
=========================

Manila share driver hooks are designed to provide additional possibilities
for each :term:`manila-share` service; such as any kind of notification and
additional actions before and after share driver calls.

Possibilities
-------------

- Perform actions before some share driver method calls.
- Perform actions after some share driver method calls with results of
    driver call and preceding hook call.
- Call additional 'periodic' hook each 'N' ticks.
- Possibility to update results of driver's action by post-running hook.

Features
--------

- Errors in hook execution can be suppressed.
- Any hook can be disabled.
- Any amount of hook instances can be run at once for each manila-share
    service.

Limitations
-----------

- Hooks approach is not asynchronous. That is, if we run hooks, and
    especially, more than one hook instance, then all of them will be executed
    in one thread.

Implementation in share drivers
-------------------------------

Share drivers can [re]define method `get_periodic_hook_data` that runs with
each execution of 'periodic' hook and receives list of shares (as parameter)
with existing access rules. So, each share driver, for each of its shares can
add/update some information that will be used then in the periodic hook.

What is required for writing new 'hook' implementation?
-------------------------------------------------------

All implementations of 'hook' interface are expected to be in
'manila/share/hooks'.
Each implementation should inherit class 'manila.share.hook:HookBase' and
redefine its abstract methods.

How to use 'hook' implementations?
----------------------------------

Just set config option 'hook_drivers' in driver's config group. For example::

    [MY_DRIVER]
    hook_drivers=path.to:FooClass,path.to:BarClass

Then all classes defined above will be initialized. In the same config group,
any config option of hook modules can be redefined too.

.. note::

    More info about common config options for hooks can be found in
    module `manila.share.hook`

Driver methods that are wrapped with hooks
------------------------------------------

- allow_access
- create_share_instance
- create_snapshot
- delete_share_instance
- delete_share_server
- delete_snapshot
- deny_access
- extend_share
- init_host
- manage_share
- publish_service_capabilities
- shrink_share
- unmanage_share
- create_share_replica
- promote_share_replica
- delete_share_replica
- update_share_replica
- create_replicated_snapshot
- delete_replicated_snapshot
- update_replicated_snapshot

Above list with wrapped methods can be extended in future.

The :mod:`manila.share.hook.py` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.hook
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
