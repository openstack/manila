Communicating with the manila team
===================================

This is a quick-and-dirty, opinionated, "how-to" on joining the
#openstack-manila chat room on `Matrix <https://matrix.org/>`_. The room
is bridged to the OFTC IRC server, so you can also use a regular IRC
client or a hosted IRC service (like
`IRC Cloud <https://www.irccloud.com/>`_) instead. However, most new
contributors struggle with the concept of staying connected, and
continuing conversations with contributors across timezones. So this
guide presents a simpler alternative. The longer, definitive guide to
IRC for OpenStack is hosted in the `OpenStack Contributor Guide.
<https://docs.openstack.org/contributors/common/irc.html>`_

Step 1: Register a "nick" on OFTC
---------------------------------
The #openstack-manila channel is hosted on the OFTC IRC server. You're going
to need a registered username on this server to speak to other users on this
channel.

* Navigate to OFTC's web interface: https://webchat.oftc.net/
* Here, you'll be able to choose a Nickname and join channels straight away.
* We recommend picking out a Nickname that's easy to remember. We highly
  recommend picking this Nickname as your `Launchpad user ID <https://launchpad
  .net/>`_ and `OpenDev Gerrit user ID <https://review.opendev.org/>`_. It
  makes things far less confusing!
* Enter the Nickname you pick in the interface, you don't need to specify
  any channels. Click, "Connect"
* In the webpage that opens, enter the following, by picking your own
  <password> and <e-mail>::

  /msg NickServ REGISTER <password> <e-mail>

* Remember to set a secure password that isn't shared with any other digital
  account. The email you enter will be used to recover the password if you
  ever forget it.

Step 2: Register on Element
---------------------------
`Element <https://app.element.io/>`_ is a popular Matrix client. You can find
a `handy desktop client or mobile app <https://element.io/download>`_ for it
too.

* Navigate to Element’s web interface: https://app.element.io/#/welcome
* Click on "Create Account"
* You must pick "matrix.org" as your home server. You may use a sign in
  provider (such as google.com, github.com, gitlab.com) if you have an account
  with any of these, or, register with your email directly and set a
  password.
* You’ll be asked to accept the terms and conditions of the service.
* If you are registering an account via email, you will be prompted to verify
  your email address.

Step 3: Join the #openstack-manila room
---------------------------------------
* In Element, click "Explore Public Rooms" (the compass icon).
  Remove the "Public Rooms" filter from the search bar (bridged
  OFTC rooms are not listed in the public directory), then search
  for ``#_oftc_#openstack-manila:matrix.org`` and click "Join".
* Alternatively, you can use `this direct link
  <https://matrix.to/#/#_oftc_#openstack-manila:matrix.org>`_
  to join the room.
* Repeat for any other OpenStack rooms you’d like to join, such as
  `#openstack-dev
  <https://matrix.to/#/#_oftc_#openstack-dev:matrix.org>`_ or
  `#openstack-meeting-alt
  <https://matrix.to/#/#_oftc_#openstack-meeting-alt:matrix.org>`_.
  See https://meetings.opendev.org/ for the full list of channels.

Step 4: Chatting across timezones
---------------------------------
* Be aware that community members may appear "online", but might actually
  not be at their computers. So messages that you send them will not be
  received until they return to their computers.
* Matrix keeps full message history, so you won't miss anything if you
  close your client. Just scroll up when you return to catch up on any
  conversation that continued while you were away.
* You can also view the `logs of the official OpenStack OFTC channels
  <https://meetings.opendev.org/irclogs/>`_ to find older conversations.
