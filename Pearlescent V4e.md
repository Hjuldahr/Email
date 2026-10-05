# **Pearlescent Unified Mail Protocol**

## **Version 4**

### **Status of This Specification**

This document defines the client/server behaviour of the Pearlescent Unified Mail Protocol (Pearlescence) Version 4\.

The specification defines observable protocol behaviour, command syntax, session state, and message operations. Database schema, socket implementation, transport security, persistence mechanisms, and other implementation details are outside the scope of this document.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as normative requirements.

**Opcode allocation:** Operation codes are grouped by command set. The most significant hexadecimal digit identifies the command set, while the remaining digits identify an operation within that set. Command sets generally correspond to protocol sections, with closely related operations merged into the same set where appropriate. Unassigned command sets and operation codes are reserved for future use. 

---

# **1\. Protocol Model**

Pearlescence provides a unified mail protocol for account management, address management, message retrieval, message mutation, drafting, sending, attachments, temporary mirror addresses, automated actions, blocking, and contacts.

Unlike protocols that separate message submission, mailbox access, and message retrieval into independent command sets, Pearlescence exposes these operations through a single authenticated session.

A server MAY expose additional commands or capabilities through capability negotiation, but a client MUST NOT assume that an optional capability is available unless the server advertises it.

---

# **2\. Framing**

## **2.1 Input Frames**

PRLSCNT\[B : PROTO VERSION\]\[I : FRAME SIZE\]\[H : OP CODE\]\[B : ARG COUNT\](\[H : ARG SIZE\]\[Raw : ARG\]...)\[I: CHECKSUM\]

Each input frame contains:

1. The `PRLSCNT` magic prefix.  
2. A protocol version number  
3. The inner frame size in bytes (op code, arg count, arg sequence, checksum).  
4. An operation code.  
5. The number of arguments.  
6. Zero or more length-prefixed arguments.  
7. A checksum calculated from the inner frame (op code, arg count, arg sequence).

## **2.2 Output Frames**

TNCSLRP\[B : PROTO VERSION\]\[I : FRAME SIZE\]\[B : STATUS\]\[H : ENTRY COUNT\](\[H : ENTRY SIZE\]\[Raw : ENTRY\]...)\[I: CHECKSUM\]

Each output frame contains:

1. The `TNCSLRP` magic prefix, to differentiate from inbound traffic.  
2. A status code:   
   * 0 \= SYNC  
   * 1 \= OK  
   * 2 \= INFO  
   * 3 \= WARN  
   * 4 \= ERROR  
3. The number of entries.  
4. Zero or more length-prefixed result entries.  
5. A checksum.

## **2.3 Magic Prefix**

PRLSCNT \= 50 52 4C 53 43 4E 54   
TNCSLRP \= 54 4E 43 53 4C 52 50 

The exact integer widths, signedness, byte order, checksum algorithm, checksum coverage, and maximum frame sizes are defined by the transport specification.

---

# **3\. Connection and Session**

## **3.1 REQ**

Opcode: 0x001

REQ

The client automatically sends `REQ` when connecting to the unsecure port.

If the connection is permitted, the server returns:

* Connection TTL  
* Required encryption profile  
* Maximum input buffer size  
* Maximum output buffer size

If the connection cannot be accepted, the server returns `NO`.

Possible reasons include address bans and temporary resource exhaustion.

**Requirement:** Sent automatically by the client.

## **3.2 HELLO**

Opcode: 0x002  
HELLO \<Client UID\>

The client automatically sends `HELLO` after establishing a secure connection.

`Client UID` identifies the client/session and establishes acceptance of the terms required for entry. It does not authenticate the client to an account.

The server returns `OK` if the connection may proceed, or `ERR` otherwise.

**Requirement:** Sent automatically by the client.

## **3.3 REGISTER**

Opcode: 0x004  
REGISTER \<Username\> \<Password Hash\>

Creates a new account.

The command fails if the username is already taken.

On success, the session enters `AUTHENTICATED` mode.

**Requirement:** CONNECTED

## **3.4 LOGIN**

Opcode: 0x005  
LOGIN \<Username\> \<Password Hash\>

Authenticates the client to an existing account.

On success, the server returns:

* The account's last login timestamp, before it is updated.  
* The number of unread messages in the inbox.

The session then enters `AUTHENTICATED` mode.

**Requirement:** None

## **3.5 LOGOUT**

Opcode: 0x006  
LOGOUT

Closes the current authenticated account session.

Before closing the account session:

1. All messages in `TRASH` MUST be permanently deleted.  
2. `MIRROR OFF` MUST be executed.

The connection itself remains open.

If the session is not authenticated, `LOGOUT` is a no-op.

**Requirement:** AUTHENTICATED

## **3.6 DC**

Opcode: 0x003  
DC

Terminates the connection.

If the session is authenticated, `LOGOUT` MUST be executed first.

`DC` is also invoked automatically when:

* The connection TTL expires without sufficient activity to refresh it.  
* A fatal connection error occurs.

**Requirement:** CONNECTED

---

# **4\. Addressing**

An account MAY have multiple registered addresses. Registered addresses share the account's mailbox.

## **4.1 ADDR REQ**

Opcode: 0x102  
ADDR REQ \<Address\>

Requests registration of an address to the current account.

The request MUST be declined if the address is already registered to another account or is registered as an alias to another account.

The server MUST NOT disclose the identifier of the account currently associated with an unavailable address.

A newly registered address defaults to `ON`.

**Design Note:** The operation is called `REQ` because availability determines whether the request can be fulfilled. `REGISTER` is reserved for the resulting authoritative account state. The distinction is analogous to requesting a seat from a reservable pool versus registering for a license.

**Requirement:** AUTHENTICATED

## **4.2 ADDR REL**

Opcode: 0x103  
ADDR REL \<Address\>

Releases an address registered to the current account.

An address not registered to the current account is a no-op.

After release, the address enters an account-reserve pool for one week. During this period, only the account that released the address MAY request it again. After the reserve period expires, the address becomes publicly available.

When an address is initially released, its enablement and forwarding state MUST be reset.

**Requirement:** AUTHENTICATED

## **4.3 ADDR**

Opcode: 0x101  
ADDR \[\<ON|OFF\>\] \<Address\>

Enables or disables an address registered to the current account.

When `OFF`, the address MUST NOT receive email.

When `ON`, the address MAY receive email.

If the argument is omitted, the server returns the address's current enablement state.

All email received through addresses registered to the same account is delivered to that account's inbox. `ACT` MAY be used to distinguish mail received through individual addresses, such as by applying tags.

**Requirement:** AUTHENTICATED

## **4.4 LIST ADDR**

Opcode: 0x100  
LIST ADDR

Returns the addresses registered to the current account.

Each address entry contains:

* Address  
* Number of unseen inbox messages received through the address  
* Enablement state

**Requirement:** AUTHENTICATED

---

# **5\. Capabilities and Session Controls**

## **5.1 LIST FEATURE**

Opcode: 0x301  
LIST FEATURE

Returns the capabilities supported by the server and whether they are enabled or disabled.

The first result entry contains the status. Each subsequent result entry contains one capability name.

**Requirement:** CONNECTED

## **5.2 FEATURE**

Opcode: 0x302  
FEATURE \[\<ON|OFF\>\] \<Features\>...

Requests activation or deactivation of one or more optional features.

If the toggle argument is omitted, the current state is returned.

**Requirement:** CONNECTED

## **5.3 VIEWONLY**

Opcode: 0x303  
VIEWONLY \[\<ON|OFF\>\]

Controls account-state modification for the current session.

The default is `OFF`.

When enabled, commands that modify account state MUST be blocked.

`VIEWONLY` itself remains available so that the mode can be disabled.

If the argument is omitted, the current state is returned.

Session-state operations are not considered account-state modifications.

**Requirement:** CONNECTED

## **5.4 NOTIFY**

Opcode: 0x304  
NOTIFY \[\<ON|OFF\>\]

Controls unsolicited inbox notifications for the current session.

The default is `ON`.

When enabled, the server sends the Message UID whenever a new message arrives in the inbox.

The client MUST still periodically communicate with the server to prevent the connection TTL from expiring.

When disabled, the server does not send inbox notifications. The client MUST query for state changes manually.

If the argument is omitted, the current state is returned.

**Requirement:** CONNECTED

## **5.5 PING**

Opcode: 0x000  
PING

Refreshes the connection TTL and returns `OK`.

**Requirement:** CONNECTED

---

# **6\. Mailbox Operations**

## **6.1 DETACH**

Opcode: 0x403  
DETACH \<Message UID\>

Permanently deletes all attachments from the specified message.

The message itself is retained.

**Requirement:** AUTHENTICATED, message in `INBOX`, `MERC`, or `JUNK`

## **6.2 MOVE**

Opcode: 0x404  
MOVE \<Folder Name\> \<Message UID\>...

Moves the specified messages between ordinary incoming-mail folders.

Supported destinations are:

* `INBOX`  
* `MERC`  
* `JUNK`

Permitted transitions are:

INBOX → JUNK  
JUNK  → INBOX  
MERC  → INBOX  
MERC  → JUNK

`MOVE` MUST NOT modify the sender address.

`ARCHIVE`, `TRASH`, `OUTBOX`, and `DRAFTS` are not valid `MOVE` destinations. These folders use dedicated commands because they have additional message-processing semantics.

**Requirement:** AUTHENTICATED, all messages in `INBOX`, `MERC`, or `JUNK`

## **6.3 FORWARD**

Opcode: 0x405  
FORWARD \<Original Message UID\> \<Recipient\> \[\<NOW\>\]

Creates a copy of the designated message from the current account's `INBOX`, `SENT`, `MERC`, or `JUNK` folder in `OUTBOX` for delivery to the designated recipient.

The forwarded copy replaces the original message's recipient fields with the supplied recipient.

The forwarded copy receives a new Message UID. The original message is not modified.

Cancelling the forwarded message moves it to `DRAFTS`, regardless of whether the original message was sent by the current account or received from another account.

`NOW` bypasses the normal `OUTBOX` delay and attempts to forward the message immediately.

If the immediate forward succeeds, the resulting message is placed in `SENT`.

**Requirement:** AUTHENTICATED, message in `INBOX`, `SENT`, `MERC`, or `JUNK`

## **6.4 SEEN**

Opcode: 0x406  
SEEN \<ON|OFF\> \<Message UIDs\>...

Manually enables or disables the seen status of the specified messages.

A message's seen status is automatically enabled when `FETCH` is used with `BOTH` or `BODYONLY`.

Messages created with `DRAFT` default to `SEEN ON`.

**Requirement:** AUTHENTICATED

## **6.5 LIST**

Opcode: 0x400  
LIST \<Folder Name\> \[\<Email Filter\>\] \[\<Range\>\]

Returns messages in the specified folder matching the supplied filter.

Available folders are:

* `INBOX`  
* `OUTBOX`  
* `DRAFTS`  
* `SENT`  
* `ARCHIVE`  
* `TRASH`  
* `JUNK`

`MERC` is available while a mirror address is active.

Results are ordered by send time.

Each message entry provides, at minimum:

* Thread UID  
* Message UID  
* Flag state  
* Tags  
* Sender address  
* Subject line, with `…` indicating truncation  
* Reply count  
* Attachment count  
* Send time  
* Unread state or read time

The email filter MAY select messages by:

* Send-time range  
* Tags, using inclusion or exclusion and glob matching  
* `From`, `To`, and `CC` addresses, using inclusion or exclusion and glob matching  
* Subject line, using inclusion or exclusion and glob matching  
* Attachment count range  
* Attachment type  
* Reply count range  
* Message size in bytes

Additional filter criteria MAY be added in future protocol versions.

**Requirement:** AUTHENTICATED

## **6.6 LIST THREAD**

Opcode: 0x401  
LIST THREAD \<Thread UID\>

Returns the Message UIDs belonging to the specified thread.

Messages are ordered by send time.

**Requirement:** AUTHENTICATED

## **6.7 FETCH**

Opcode: 0x407  
FETCH \[\<METAONLY|BODYONLY\>\] \<Message UID\> \[\<Range\>\]

Retrieves the specified message.

If neither `METAONLY` nor `BODYONLY` is supplied, both metadata and body are returned in separate frames.

### **Metadata**

Metadata contains, at minimum:

* Timestamps  
* Message size  
* Addressing  
* Current folder  
* Current state

Additional metadata MAY be included.

### **Body**

The body contains the message payload.

A range MAY specify an offset and/or end position to retrieve only part of the payload.

If the requested body exceeds the maximum output frame size, the response is truncated to fit.

Range semantics are byte-based.

**Requirement:** AUTHENTICATED

## **6.8 DELETE**

Opcode: 0x408  
DELETE \<Message UIDs\>...

Moves the specified messages to `TRASH`.

Before moving each message, its previous folder is prepended to the subject line. This preserves a visible and searchable indication of the message's origin.

**Requirement:** AUTHENTICATED

## **6.9 RESTORE**

Opcode: 0x409  
RESTORE \<Message UIDs\>...

Restores messages from `TRASH` or `ARCHIVE` to their previous folder.

The origin prefix added by `DELETE` or `ARCH` is removed from the subject line.

**Requirement:** AUTHENTICATED

## **6.10 ARCH**

Opcode: 0x40A  
ARCH \<Message UIDs\>...

Moves the specified messages from their current folders to `ARCHIVE`.

Before moving each message, its previous folder is prepended to the subject line.

**Requirement:** AUTHENTICATED

## **6.11 FLAG**

Opcode: 0x40B  
FLAG \<ON|OFF\> \<Message UIDs\>...

Enables or disables the flag on the specified messages.

**Requirement:** AUTHENTICATED

## **6.12 TAG**

Opcode: 0x40C  
TAG \<ON|OFF\> \<Tag\> \<Message UIDs\>...

Adds or removes a tag from the specified messages.

When adding a tag, the tag is created if it does not already exist.

When removing a tag, the tag is deleted if it has no remaining message associations.

**Requirement:** AUTHENTICATED

## **6.13 LIST TAG**

Opcode: 0x402  
LIST TAG

Returns the tags currently in use by the account.

Each tag entry provides:

* Tag name  
* Number of associated messages  
* Creation time

**Requirement:** AUTHENTICATED

---

# **7\. Drafts and Sending**

## **7.1 DRAFT**

Opcode: 0x501  
DRAFT \[\<Thread UID\>\] \<Recipient Addresses\> \<Subject Line\> \<Payload Size\>

Creates a draft message and prepares the connection to receive its body payload.

The recipient address format is:

TO:\<Comma Delimited\>,CC:\<Comma Delimited\>,BCC:\<Comma Delimited\>

Unused recipient fields MAY be omitted.

A trailing comma marks the beginning of the next recipient block.

The server sends `OK` when it is ready to receive the payload.

The server stops receiving the payload once the declared payload size has been reached or exceeded.

When the upload finishes, the server returns `OK` with the assigned Message UID.

If a Thread UID is supplied, the draft is associated with that thread and is sent as a reply rather than as a new thread.

**Requirement:** AUTHENTICATED

## **7.2 EDIT ADDR**

Opcode: 0x502  
EDIT \<Message UID\> ADDR \<Recipient Addresses\>

Replaces the recipients of the specified draft.

The recipient format is the same as `DRAFT`.

**Requirement:** AUTHENTICATED, message in `DRAFTS`

## **7.3 EDIT THREAD**

Opcode: 0x503  
EDIT \<Message UID\> THREAD \[\<Thread UID\>\]

Sets the thread UID of the specified draft.

If the Thread UID is omitted, the draft is detached from its current thread.

**Requirement:** AUTHENTICATED, message in `DRAFTS`

## **7.4 EDIT SUBJ**

Opcode: 0x504  
EDIT \<Message UID\> SUBJ \<Subject Line\>

Replaces the subject of the specified draft.

**Requirement:** AUTHENTICATED, message in `DRAFTS`

## **7.5 EDIT BODY**

Opcode: 0x505  
EDIT \<Message UID\> BODY \<Range\>

Replaces part of the body of the specified draft.

The client subsequently sends the replacement payload as a raw stream using the same transfer mechanism as `DRAFT`.

The range identifies the portion of the existing body being replaced.

The offset is optional. The end position is mandatory when a range is supplied.

**Requirement:** AUTHENTICATED, message in `DRAFTS`

## **7.6 SEND**

Opcode: 0x506  
SEND \<Message UID\> \[\<NOW|ABORT\>\]

Moves the specified draft from `DRAFTS` to `OUTBOX`.

A message in `OUTBOX` is automatically moved to `SENT` one minute after entering `OUTBOX`.

The one-minute delay begins when the message enters `OUTBOX`, rather than when the draft was originally created or edited.

`NOW` attempts to send the message immediately, bypassing the normal `OUTBOX` delay.

If the immediate attempt succeeds, the message is placed in `SENT`.

If the immediate attempt fails, the message remains in `DRAFTS`.

If the server is throttling outbound traffic because of an outbound backlog, the message is instead placed in `OUTBOX` for normal outbound processing.

ABORT moves the specified messages from `OUTBOX` back to `DRAFTS`, cancelling their pending send.

**Requirement:** AUTHENTICATED, message in `DRAFTS`

---

# **8\. Attachments**

## **8.1 LIST ATTACH**

Opcode: 0x600  
LIST ATTACH \<Message UID\>

Outputs a list of file attachment indexes, stems, suffixes, sizes in bytes, and number of downloads for the given message UID

**Requirement:** AUTHENTICATED

## **8.2 DOWNLOAD**

Opcode: 0x601  
DOWNLOAD \<Message UID\> \[\<Archive Type|Attachment Index\>\]

Downloads attachments from a message in `INBOX`.

Supported archive types are:

* `ZIP`  
* `TAR`  
* `TARGZ`  
* `7ZIP`

If an attachment index is supplied, only that attachment is downloaded.

If an archive type is supplied without an attachment index, all attachments are packaged into the requested archive format.

**Requirement:** AUTHENTICATED, message in `INBOX`

## **8.3 UPLOAD**

Opcode: 0x602  
UPLOAD \<Message UID\> \[\<\*|Attachment Index\>\]

Uploads an attachment to a message in `DRAFTS`.

If no attachment index is supplied, the uploaded file is appended as a new attachment.

If an attachment index is supplied, that attachment is replaced.

If `*` is supplied, the uploaded file is treated as an unencrypted archive and its contents are imported as attachments.

Password-protected archives cannot be opened.

Archive import operates on top-level files and nested archives. Nested archives are imported as individual attachments rather than recursively unpacked.

Normal directories and links are ignored.

An error is returned if the specified attachment index does not exist.

Attachment size is inferred from the uploaded file rather than being supplied as a command argument.

`DRAFT` and `UPLOAD` cannot transfer data simultaneously. Body data and attachment data use separate framing and security boundaries.

**Requirement:** AUTHENTICATED, message in `DRAFTS`

---

# **9\. Mirror Addresses**

## **9.1 MIRROR**

Opcode: 0x700  
MIRROR \[\<ON|OFF\>\]

Controls the mirror address for the current authenticated session.

When enabled, the server provides a mirror address consisting of:

\<timestamp\>\<random hash\>@\<pearlescent domain\>

The generated address contains a random, currently unclaimed hash.

If the argument is omitted, the current mirror address is returned.

When switched `OFF`, the mirror is discarded and will no longer be served.

A mirror differs from an alias because it obscures the underlying base address while continuing to deliver messages to the same account through the `MERC` folder.

`MERC` is short for *Mercurial*.

The `MERC` folder is visible only while a mirror is active. Disabling the mirror permanently purges `MERC` and all messages contained within it.

Mirror addresses are intended primarily for temporary registrations that require an email address, such as one-time-password registration.

**Requirement:** AUTHENTICATED

---

# **10\. Actions**

Actions provide server-side automated processing of messages.

Actions are evaluated according to their configured priority and execution order. The order of operations is significant both within a single action and among multiple actions matching the same message.

## **10.1 ACT**

Opcode: 0x801  
ACT \[\<UID\> DEL\]  
  | \[\<Priority\> \<Filter\> (\<Action\>...)\]  
  | \[\<UID\> \<Priority\> \<Filter\> (\<Action\>...)\]

Creates, edits, or deletes an account action.

If no UID is supplied, a new action is created.

If a UID and `DEL` are supplied, the specified action is deleted.

If a UID and an action definition are supplied, the specified action is edited.

Newly created actions are enabled by default.

The server returns the Action UID when an action is created.

**Requirement:** AUTHENTICATED

## **10.2 Action Operations**

The following action operations are supported:

FLAG  
SEEN  
TAG \<Comma Delimited Tags\>  
DELETE \[\<NOW\>\]  
ARCH  
REPLY \<TEXT\>  
FORWARD \<Address\>  
DOWN \<Archive Format\>  
DETACH

### **FLAG**

Sets the message's flagged state to `ON`.

An action cannot automatically clear an existing flag.

### **SEEN**

Sets the message's seen state to `ON`.

An action cannot automatically clear an existing seen state.

### **TAG**

TAG \<Comma Delimited Tags\>

Adds the specified tags to the message.

Missing tags are created automatically.

### **DELETE**

DELETE \[\<NOW\>\]

Moves the message to `TRASH`.

If `NOW` is supplied, the message is permanently deleted rather than moved to `TRASH`.

### **ARCH**

Moves the message to `ARCHIVE`.

### **REPLY**

REPLY \<TEXT\>

Automatically sends a reply containing the specified text.

The following substitution is supported:

%NAME%

`%NAME%` resolves to the sender's contact name when one exists. Otherwise, it resolves to the sender's address.

### **FORWARD**

FORWARD \<Address\>

Automatically forwards a copy of the message to the specified address.

### **DOWN**

DOWN \<Archive Format\>

Packages the message's attachments using the specified archive format and makes the resulting archive available for download when the message enters `INBOX`.

`NOTIFY` MUST be `ON` for `DOWN` to operate.

### **DETACH**

Removes the message's attachments.

### **Action Ordering**

The order of actions is significant.

This applies both to operations within a single `ACT` and to the order in which multiple matching actions are executed.

For example:

DOWN ZIP  
DETACH

packages the attachments before removing them.

Conversely:

DETACH  
DOWN ZIP

leaves no attachments for `DOWN` to package.

## **10.3 ACT ON/OFF**

Opcode: 0x801  
ACT \<ON|OFF\> \<Action UID\>...

Enables or disables the specified actions.

**Requirement:** AUTHENTICATED

## **10.4 LIST ACT**

Opcode: 0x800  
LIST ACT

Returns the account's actions.

Each action entry provides:

* Action UID  
* Enabled state  
* Priority  
* Filter  
* Configured operations

**Requirement:** AUTHENTICATED

---

# **11\. Blocking**

## **11.1 BLOCK**

Op Code: 0x901  
BLOCK \<ON|OFF\> \<Address\>...

Adds or removes addresses from the account's block list.

Blocked addresses cannot send messages to or receive messages from the account.

Addresses MAY be blocked by base address or alias.

**Requirement:** AUTHENTICATED

## **11.2 LIST BLOCK**

Op Code: 0x900  
LIST BLOCK

Returns the addresses currently on the block list and the time each address was blocked.

**Requirement:** AUTHENTICATED

---

# **12\. Contacts**

## **12.1 CONTACT ADD**

Op Code: 0xA02  
CONTACT ADD \<Name\> \<Address\> \[\<About\>\]

Adds an address to the contact list.

The optional `About` field stores descriptive information about the contact.

**Requirement:** AUTHENTICATED

## **12.2 CONTACT REM**

Op Code: 0xA03  
CONTACT REM \<Address\>

Removes a contact from the contact list.

**Requirement:** AUTHENTICATED

## **12.3 LIST CONTACT**

Op Code: 0xA00  
LIST CONTACT

Returns the account's contacts.

Each contact entry provides:

* Contact name  
* Address  
* About information, if present  
* Time added  
* Number of messages received from the contact  
* Number of messages sent to the contact  
* Block status

**Requirement:** AUTHENTICATED

## **12.4 CONTACT**

Op Code: 0xA01  
CONTACT \[\<ON|OFF\>\]

Controls contact aliasing for the current session.

The default is `ON`.

When enabled, contact names MAY substitute for addresses in supported command inputs and outputs.

When disabled, contact aliasing is disabled and addresses are used directly.

If the argument is omitted, the current state is returned.

**Requirement:** AUTHENTICATED

---

# **13\. Status**

## **13.1 STATUS**

Opcode: 0x300  
STATUS

Returns account status information, including the number of messages in each folder.

Additional status information MAY be included.

**Requirement:** AUTHENTICATED

---

# **14\. Folder Semantics**

Pearlescence defines the following persistent folders:

INBOX  
OUTBOX  
DRAFTS  
SENT  
ARCHIVE  
TRASH  
JUNK

`MERC` is an ephemeral folder associated with an active mirror address.

`MERC` is visible only while a mirror is active.

Messages entering `MERC` may be moved to:

MERC → INBOX  
MERC → JUNK

Messages left in `MERC` when the mirror is disabled are permanently purged.

`TRASH`, `ARCHIVE`, `OUTBOX`, and `DRAFTS` have dedicated commands rather than being general-purpose `MOVE` destinations because their transitions carry additional semantics.

---

# **15\. Message Identity**

Messages are identified by Message UID.

A forwarded message is a new message and therefore receives a new Message UID.

Thread UIDs identify conversations independently of individual Message UIDs.

Action UIDs identify configured account actions independently of message identity.

Client UIDs identify client/session instances and MUST NOT be interpreted as account identifiers.

---

# **16\. Interoperability Mapping**

Pearlescence is designed to consolidate capabilities traditionally divided among SMTP, POP, and IMAP.

The following conceptual mappings illustrate the intended relationship rather than defining wire-compatible aliases:

IMAP FETCH ─────┐  
POP RETR ───────┼──\> Pearlescence FETCH  
IMAP SEARCH ────┤  
POP TOP ────────┘

IMAP STORE ─────┐  
IMAP MOVE ──────┤  
IMAP COPY ──────┼──\> Pearlescence message operations  
POP DELE ───────┘

IMAP SELECT ────┐  
IMAP EXAMINE ───┼──\> Pearlescence folder/session operations  
POP mailbox ────┘

SMTP MAIL ─────┐   
SMTP RCPT ─────┼──\> Pearlescence DRAFT   
SMTP DATA ─────┘ 

SMTP remains supported for interoperability with external mail systems.

---

# **17\. Open Transport Questions**

The following are intentionally outside the command semantics of this document and are to be defined by the transport specification:

* Integer widths  
* Integer signedness  
* Byte order  
* Checksum algorithm  
* Checksum coverage  
* Maximum frame sizes  
* Encryption profiles  
* Connection TTL units and minimum refresh behavior  
* Exact unsolicited-frame association rules while `NOTIFY` is enabled  
* Raw-stream framing details for `DRAFT`, `EDIT BODY`, and `UPLOAD`  
* Exact byte-range boundary semantics  
* Error/status code definitions

These details MUST NOT be inferred from implementation behaviour when a transport specification is available.

