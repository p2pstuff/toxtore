Things we know how to do
------------------------

- Option storage in Toxtore, so that Toxtore itself and the client using it
  can save configuration options and synchronize them between devices

- Store the user's nickname and status message in the Toxtore DB and
  automatically set it on all their devices (this should be optional)

- Store friend nicknames & status messages in shared DB
  (low priority, should be optional anyways and disabled by default)

- Storage homeserver: a daemon that does nothing but act as a user's device
  with the benefit of being online all the time to send and receive messages
  on their behalf


Things that we haven't figured out yet
--------------------------------------

- Figure out a robust way of preventing multiple sending of messages
  when a peer comes back online

- Group chats: think more about the semantics of synchronization
  One important question: if a user joins a chat room from one device,
  do we want the other devices to join as well? But then all the messages
  will be received multiple times, this isn't ok.

- Figure out how to do file sharing in the multi-device world

- DB cleanup of obsolete events (requires handling of histories with
  holes, i.e. missing sequence numbers)


Advanced features we might want for later
-----------------------------------------

- Allow devices to not store the full event history (e.g. only events of the
  last n days). Different devices can have different policies.

- Split events into channels and allow for different storage policies on each
  channel

- Use the storage of other people to retrieve recent chat room history when
  joining a public channel
  
