Experimental APIs
=================

Background
----------

Manila uses API microversions to allow natural evolution of its REST APIs
over time.  But microversions alone cannot solve the question of how to
ship APIs that are experimental in nature, are expected to change at any
time, and could even be removed entirely without a typical deprecation
period.

In conjunction with microversions, manila has added a facility for marking
individual REST APIs as experimental.  To call an experimental API, clients
must include a specific HTTP header, ``X-OpenStack-Manila-API-Experimental``,
with a value of ``True``.  If a user calls an experimental API without
including the experimental header, the server would respond with ``HTTP/404``.
This forces the client to acknowledge the experimental status of the API and
prevents anyone from building an application around a manila feature without
realizing the feature could change significantly or even disappear.

On the other hand, if a request is made to a non-experimental manila API with
``X-OpenStack-Manila-API-Experimental: True``, the server would respond as if
the header had not been included.  This is a convenience mechanism, as it
allows the client to specify both the requested API version as well as the
experimental header (if desired) in one place instead of having to set the
headers separately for each API call (although that would be fine, too).

When do I need to set an API experimental?
------------------------------------------

An API should be marked as experimental if any of the following is true:

- the API is not yet considered a stable, core API

- the API is expected to change in later releases

- the API could be removed altogether if a feature is redesigned

- the API controls a feature that could change or be removed

When do I need to remove the experimental annotation from an API?
-----------------------------------------------------------------

When the community is satisfied that an experimental feature and its APIs
have had sufficient time to gather and incorporate user feedback to consider
it stable, which could be one or more OpenStack release cycles, any relevant
APIs must be re-released with a microversion bump and without the experimental
flag. The maturation period can vary between features, but experimental is NOT
a stable state, and an experimental feature should not be left in that state
any longer than necessary.

Because experimental APIs have no conventional deprecation period, the manila
core team may optionally choose to remove any experimental versions of an API
at the same time that a microversioned stable version is added.

In Code
-------

The ``@api_version`` decorator defined in ``manila/api/openstack/wsgi.py``,
which is used for specifying API versions on top-level Controller methods,
also allows for tagging an API as experimental. For example:

In the controller class::

    @wsgi.Controller.api_version("2.4", experimental=True)
    def my_api_method(self, req, id):
        ....

This method would only be available if the caller had specified an
``X-OpenStack-Manila-API-Version`` of >= ``2.4``. and had also included
``X-OpenStack-Manila-API-Experimental: True``. If they had specified a
lower version (or not specified it and received a lower default version),
or if they had failed to include the experimental header, the server would
respond with ``HTTP/404``.
