User Messages
=============

User messages are a way to inform users about the state of asynchronous
operations. One example would be notifying the user of why a share
provisioning request failed. These messages can be requested via the
`/messages` API. All user visible messages must be defined in the permitted
messages module in order to prevent sharing sensitive information with users.


Example message generation::

 from manila import context
 from manila.message import api as message_api
 from manila.message import message_field

 self.message_api = message_api.API()

 context = context.RequestContext()
 project_id = '6c430ede-9476-4128-8838-8d3929ced223'
 share_id = 'f292cc0c-54a7-4b3b-8174-d2ff82d87008'

 self.message_api.create(
     context,
     message_field.Actions.CREATE,
     project_id,
     resource_type=message_field.Resource.SHARE,
     resource_id=SHARE_id,
     detail=message_field.Detail.NO_VALID_HOST)

Will produce the following::

 GET /v2/6c430ede-9476-4128-8838-8d3929ced223/messages
 {
   "messages": [
     {
      "id": "5429fffa-5c76-4d68-a671-37a8e24f37cf",
      "action_id": "001",
      "detail_id": "002",
      "user_message": "create: No storage could be allocated for this share "
                      "request. Trying again with a different size "
                      "or share type may succeed."",
      "message_level": "ERROR",
      "resource_type": "SHARE",
      "resource_id": "f292cc0c-54a7-4b3b-8174-d2ff82d87008",
      "created_at": 2015-08-27T09:49:58-05:00,
      "expires_at": 2015-09-26T09:49:58-05:00,
      "request_id": "req-936666d2-4c8f-4e41-9ac9-237b43f8b848",
     }
   ]
 }



The Message API Module
----------------------

.. automodule:: manila.message.api
    :noindex:
    :members:
    :undoc-members:

The Permitted Messages Module
-----------------------------

.. automodule:: manila.message.message_field
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
