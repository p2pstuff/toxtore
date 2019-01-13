# Proposal for Multi-Device Tox : Toxtore

## Abstract

Multi-device synchronization for Tox as a non-disruptive layer above current `toxcore` library.

Expected features:

- does not break compatibility with people who do not have a multi-device-enabled version
- history synchronization between a user's devices for friend and group messages
- read status of messages is synchronized between devices
- friend list synchronization between devices
- no complex coordination required, no master/slave device, all are equal and synchronize as soon as they are connected
- a message to an offline friend can be sent from one device on the behalf of another when the friend comes back online
- a user's device can be a daemon running on a server somewhere, ensuring 100% message reception and possibility of synchronizing


## Main points

- one device = one Tox ID
- a device will say "my user is also these and these other Tox IDs" so that peers can merge them into one virtual contact
- each device keeps a personnal log of events
- each device fetches the logs of the other linked devices and merges all in one "global" view

## Event types

An event is uniquely identified by a dot, which is a pair of the Tox ID of the
device on which it was generated and its sequence number in the log of that
device. Some events refer to other past events by their dot.

Some events act as last-writer-wins registries:
- friend add/delete (= a LWW boolean)
- friend nospam info
- friend device info
- (when we add it) friend nickname, status message

Messages are unique events to which flags (sent successfull, mark read) are applied.
It doesn't matter if these flags are applied many times.

```
-- friend add/del
arg_pk = friend pk
arg_int = is friend? (1 = is friend / friend added, 0 = not friend / friend deleted)
cache_flag = obsolete?

-- friend nospam info
arg_pk = friend pk
arg_blob = nospam + checksum
cache_flag = obsolete?

-- friend devices changed
arg_pk = friend pk
arg_blob = list of other device pks
cache_flag = obsolete?

-- try send message
arg_pk = to pk
arg_int = message type (TOX_MESSAGE_TYPE)
arg_msg = message
cache_flag = done?

-- try send message in group
arg_blob = group id
arg_int = message type (TOX_MESSAGE_TYPE)
arg_msg = message
cache_flag = done?

-- done send message
dot = dot of try send event

-- recv message
arg_pk = from who
arg_int = message type (TOX_MESSAGE_TYPE)
arg_msg = msg
cache_flag = read?

-- recv message in group
arg_pk = from who
arg_int = message type (TOX_MESSAGE_TYPE)
arg_blob = group id
arg_msg = message
cache_flag = read?

-- mark message read
dot = dot of recv message event
```

## Protocol packet types

```
-- my devices
type : uint8_t = 1
n_devices : uint8_t
devices : pk * n_devices

-- device add req
type : uint8_t = 2

-- vector clock
type : uint8_t = 3
n_devices : uint8_t
vector_clock : [pk, got_until : uint64_t] * n_devices

-- send dot header
type : uint8_t = 4
dot_dev_pk : pk
dot_seq_no : uint64_t
dot_type : uint8_t = TOXTORE_EVENT_FRIEND_*
timestamp : uint64_t

-- send dot : event friend adddel
header
friend : pk
obsolete? : uint8_t
is friend : uint8_t

-- send dot : event friend nospam value changed
header
friend : pk
obsolete : uint8_t
data : nospam + checksum

-- send dot : friend devices changed
header
friend : pk
obsolete : uint8_t
n_devices : uint8_t
devices : pk * n_devices

-- send dot : try send message
header
to : pk
send_done : uint8_t
type : uint8_t
msg_len : uint32_t
msg : bytes

-- send dot : try send message in conference
header
to : conf_id
send_done : uint8_t
type : uint8_t
msg_len : uint32_t
msg : bytes

-- send dot : done send msg
header
arg_dot_dev : pk
arg_dot_sn : uint64_t

-- send dot : friend recv
header
from : pk
read? : uint8_t
type : uint8_t
msg_len : uint32_t
msg : bytes

-- send dot : conference recv
header
from : pk
group : conf_id
read? : uint8_t
type : uint8_t
msg_len : uint32_t
msg : bytes

-- send dot : mark message read
header
arg_dot_dev : pk
arg_dot_sn : uint64_t
```
