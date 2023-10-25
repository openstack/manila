Communicating with the manila team over IRC
===========================================

This is a quick-and-dirty, opinionated, "how-to" on connecting from
`Matrix <https://matrix.org/>`_ to the OFTC IRC server to chat with the
#openstack-manila team. You don't need this method if you're willing to use
a regular IRC client, or a hosted IRC service (like
`IRC Cloud <https://www.irccloud.com/>`_). However, most new contributors
struggle with the concept of staying connected, and continuing conversations
with contributors across timezones. So this guide presents a simpler
alternative. The longer, definitive guide to IRC for OpenStack is hosted
in the `OpenStack Contributor Guide.
<https://docs.openstack.org/contributors/common/irc.html>`_

Step 1: Register a "nick" on OFTC
---------------------------------
The #openstack-manila channel is hosted on the OFTC IRC server. You're going
to need a registered username on this server to speak to other users on this
channel.

* Navigate to OFTC's web interface: https://webchat.oftc.net/
* Here, you'll be able to choose a Nickname and join channels straight away.
* We recommend picking out a Nickname that's easy to remember. We highly
  recommend picking this Nicknam as your `Launchpad user ID <https://launchpad
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

* Navigate to Element's web interface: https://app.element.io/#/welcome
* Click on "Create Account"
* You must pick "matrix.org" as your home server. You may use a sign in
  provider (such as google.com, github.com, gitlab.com) if you have an account
  with any of these, or, register with your email directly and a set a
  password.
* You’ll be asked to accept the terms and conditions of the service.
* If you are registering an account via email, you will be prompted to verify
  your email address.

Step 3: Join the #openstack-manila channel
------------------------------------------
* On Element, Start a chat with `@oftc-irc:matrix.org`
* The following commands are entered into this chat window.
* Set your username to the nickname you registered in Step 1::

    !username <Nickname>
* Provide your password::

    !storepass <Password>
* Log in by issuing::

   !reconnect
* Join the #openstack-manila channel::

   !join #openstack-manila

* Repeat the above step for any channel you'd like to join on OFTC

Step 4: Chatting across timezones
---------------------------------
* Be aware that community members may appear "online", but might actually
  not be at their computers. So messages that you send them will not be
  received until they return to their computers.
* So be sure view `logs of the official OpenStack OFTC channels
  <https://meetings.opendev.org/irclogs/>`_ in case you started a
  conversation that picked up asynchronously.
