```

## Account Ownership

`account.account_id` is an internal database identifier and is never required to represent an email address.

`address.address` is the authoritative externally visible address.

An address is unique across the entire server:

```text
address.address UNIQUE
```

An address belongs to an account through `address.account_id`.

The `is_alias` field distinguishes a base address from an alias without changing the address's externally visible identity.

## Message Addressing

Messages deliberately do not contain:

```text
sender_address_id
recipient_address_id
```

Instead, they contain the literal addresses:

```text
message.sender_address
message_recipient.address
```

This is important for SMTP/POP/IMAP interoperability.

For example, Pearlescence can receive:

```text
From: external@example.org
To: user@pearlescent.example
```

without `external@example.org` ever being registered as a Pearlescence address.

Likewise, an old POP/IMAP message can be imported without first creating database records for every address appearing in its headers.

The database may still use internal IDs for **account ownership, tags, contacts, attachments, actions, and other server-owned objects** because those objects do not represent externally addressable identities.

## Message Identity

`message_id` is an internal database primary key.

`message_uid` is the protocol-visible Message UID.

The distinction means the database can freely change its physical representation without changing the UID exposed to clients.

The same principle applies to:

```text
thread_uid
action_uid
```

## Folder Representation

The `folder` field represents the message's current mailbox.

`MERC` is represented as a folder value even though it is ephemeral.

When a mirror is disabled, messages with:

```text
folder = 'MERC'
```

are permanently deleted.

No `previous_folder` column is required. `DELETE` and `ARCH` intentionally encode the previous folder into the subject, allowing `RESTORE` to recover the origin from the user-visible message state.

## OUTBOX Scheduling

`outbox_at` records the instant at which the message entered `OUTBOX`.

This is the timestamp relevant to the normal one-minute sending delay.

It is deliberately separate from:

```text
created_at
updated_at
```

so editing a draft cannot accidentally extend or shorten the outbound cancellation window after `SEND`.

`send_after` can represent the resulting scheduled delivery time:

```text
send_after = outbox_at + INTERVAL 1 MINUTE
```

For `SEND ... NOW`, the message does not need to enter `OUTBOX` unless the server is forced to queue it because of outbound throttling.

## Recipient Ordering

`recipient_order` preserves the order supplied by the client.

This is useful because the protocol's recipient representation is ordered, while SQL relations themselves are not.

## Attachments

`attachment_index` is scoped to the message:

```text
(message_id, attachment_index)
```

Therefore the protocol's attachment index can remain stable and does not depend on a global attachment ID.

`attachment_id` is only an internal database identifier.

## Actions

The filter and operation syntax is stored separately from the action's identity and scheduling metadata.

A possible representation is:

```json
{
    "from": {
        "include": ["*.example.com"]
    },
    "subject": {
        "exclude": ["*newsletter*"]
    }
}
```

and:

```json
[
    ["TAG", ["news"]],
    ["FORWARD", "archive@example.com"]
]
```

The exact JSON representation is not part of V4. The protocol can serialize/deserialize its action definition independently.

## Address Reservation

Released addresses are removed from `address` and placed into `address_reservation`.

Thus an address cannot simultaneously be:

```text
registered
```

and:

```text
reserved-for-reclaim
```

A scheduled cleanup can remove reservations after `reserved_until`, making the address available to `ADDR REQ`.

## Mirror Delivery

A mirror's actual address is stored in `mirror.address`.

Incoming mail delivered through the mirror can be represented as:

```text
message.folder = 'MERC'
```

with an optional `message_mirror` record identifying which active mirror accepted it.

The sender remains:

```text
message.sender_address
```

and is never replaced with the mirror address.

This keeps mirror delivery separate from ordinary message addressing.