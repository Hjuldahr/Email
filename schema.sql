DROP DATABASE IF EXISTS pearlescence;
CREATE DATABASE pearlescence
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

USE pearlescence;

-- ============================================================
-- Accounts
-- ============================================================

CREATE TABLE account (
    account_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARBINARY(512) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_login_at DATETIME(6) NULL
);


-- ============================================================
-- Addresses
--
-- The address string is the externally meaningful identity.
-- Messages therefore do NOT reference address_id.
-- ============================================================

CREATE TABLE address (
    address_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    address VARCHAR(254) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    registered_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    UNIQUE KEY uq_address (address),
    KEY ix_address_account (account_id),

    CONSTRAINT fk_address_account
        FOREIGN KEY (account_id)
        REFERENCES account(account_id)
        ON DELETE CASCADE
);


-- ============================================================
-- Released-address reserve pool
--
-- Kept separately from address because a released address no
-- longer belongs to the account.
-- ============================================================

CREATE TABLE address_reservation (
    reservation_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    address VARCHAR(254) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    released_at DATETIME(6) NOT NULL,
    reserved_until DATETIME(6) NOT NULL,

    UNIQUE KEY uq_reserved_address (address),
    KEY ix_reservation_account (account_id),
    KEY ix_reservation_expiry (reserved_until),

    CONSTRAINT fk_reservation_account
        FOREIGN KEY (account_id)
        REFERENCES account(account_id)
        ON DELETE CASCADE
);


-- ============================================================
-- Messages
--
-- sender_address and all recipient addresses are stored as
-- strings rather than references to address.address_id.
--
-- This permits messages originating from external SMTP systems
-- and permits POP/IMAP compatibility without requiring the
-- external address to exist in the Pearlescence address table.
-- ============================================================

CREATE TABLE message (
    message_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    -- Protocol-visible identifiers.
    message_uid BINARY(16) NOT NULL UNIQUE,
    thread_uid BINARY(16) NULL,

    sender_address VARCHAR(254) NOT NULL,

    subject VARCHAR(998) NOT NULL,
    body LONGBLOB NOT NULL,

    folder ENUM(
        'INBOX',
        'DRAFTS',
        'OUTBOX',
        'SENT',
        'ARCHIVE',
        'JUNK',
        'TRASH',
        'MERC'
    ) NOT NULL,

    flagged BOOLEAN NOT NULL DEFAULT FALSE,
    seen BOOLEAN NOT NULL DEFAULT TRUE,

    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    received_at DATETIME(6) NULL,
    sent_at DATETIME(6) NULL,
    read_at DATETIME(6) NULL,

    -- When an Outbox message entered Outbox.
    outbox_at DATETIME(6) NULL,

    -- Optional delivery scheduling/processing timestamp.
    send_after DATETIME(6) NULL,

    KEY ix_message_folder_time (folder, sent_at, message_id),
    KEY ix_message_thread (thread_uid),
    KEY ix_message_sender (sender_address),
    KEY ix_message_seen (folder, seen),
    KEY ix_message_flagged (folder, flagged)
);


-- ============================================================
-- Message recipients
--
-- Addresses are deliberately stored as strings.
-- recipient_type corresponds to TO / CC / BCC.
-- ============================================================

CREATE TABLE message_recipient (
    recipient_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    message_id BIGINT UNSIGNED NOT NULL,

    recipient_type ENUM('TO', 'CC', 'BCC') NOT NULL,
    address VARCHAR(254) NOT NULL,
    recipient_order INT UNSIGNED NOT NULL DEFAULT 0,

    KEY ix_recipient_message (message_id, recipient_type, recipient_order),
    KEY ix_recipient_address (address),

    CONSTRAINT fk_recipient_message
        FOREIGN KEY (message_id)
        REFERENCES message(message_id)
        ON DELETE CASCADE
);


-- ============================================================
-- Message tags
-- ============================================================

CREATE TABLE tag (
    tag_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    UNIQUE KEY uq_tag_account_name (account_id, name),

    CONSTRAINT fk_tag_account
        FOREIGN KEY (account_id)
        REFERENCES account(account_id)
        ON DELETE CASCADE
);


CREATE TABLE message_tag (
    message_id BIGINT UNSIGNED NOT NULL,
    tag_id BIGINT UNSIGNED NOT NULL,

    PRIMARY KEY (message_id, tag_id),

    CONSTRAINT fk_message_tag_message
        FOREIGN KEY (message_id)
        REFERENCES message(message_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_message_tag_tag
        FOREIGN KEY (tag_id)
        REFERENCES tag(tag_id)
        ON DELETE CASCADE
);


-- ============================================================
-- Attachments
-- ============================================================

CREATE TABLE attachment (
    attachment_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    message_id BIGINT UNSIGNED NOT NULL,

    attachment_index INT UNSIGNED NOT NULL,
    filename VARCHAR(255) NOT NULL,
    content_type VARCHAR(255) NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    payload LONGBLOB NOT NULL,

    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    UNIQUE KEY uq_attachment_index (message_id, attachment_index),

    CONSTRAINT fk_attachment_message
        FOREIGN KEY (message_id)
        REFERENCES message(message_id)
        ON DELETE CASCADE
);


-- ============================================================
-- Contacts
-- ============================================================

CREATE TABLE contact (
    contact_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,

    name VARCHAR(255) NOT NULL,
    address VARCHAR(254) NOT NULL,
    about TEXT NULL,

    added_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    UNIQUE KEY uq_contact_account_address (account_id, address),
    KEY ix_contact_account_name (account_id, name),

    CONSTRAINT fk_contact_account
        FOREIGN KEY (account_id)
        REFERENCES account(account_id)
        ON DELETE CASCADE
);


-- ============================================================
-- Block list
--
-- Addresses are stored directly because external addresses can
-- be blocked without being registered in Pearlescence.
-- ============================================================

CREATE TABLE block (
    block_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,

    address VARCHAR(254) NOT NULL,
    blocked_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    UNIQUE KEY uq_block_account_address (account_id, address),

    CONSTRAINT fk_block_account
        FOREIGN KEY (account_id)
        REFERENCES account(account_id)
        ON DELETE CASCADE
);


-- ============================================================
-- Account actions
--
-- Filter/action syntax is protocol-level data. Storing it as
-- JSON keeps the schema independent of the eventual filter
-- grammar while still allowing structured storage.
-- ============================================================

CREATE TABLE action (
    action_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    -- Protocol-visible Action UID.
    action_uid BINARY(16) NOT NULL UNIQUE,

    account_id BIGINT UNSIGNED NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INT NOT NULL,

    filter JSON NOT NULL,
    operations JSON NOT NULL,

    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),

    KEY ix_action_account_priority (account_id, enabled, priority),

    CONSTRAINT fk_action_account
        FOREIGN KEY (account_id)
        REFERENCES account(account_id)
        ON DELETE CASCADE
);


-- ============================================================
-- Mirror addresses
--
-- A mirror has its own address string and points to the account.
-- Messages received through it are assigned to MERC.
-- ============================================================

CREATE TABLE mirror (
    mirror_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    account_id BIGINT UNSIGNED NOT NULL,
    address VARCHAR(254) NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    disabled_at DATETIME(6) NULL,

    UNIQUE KEY uq_mirror_address (address),
    UNIQUE KEY uq_mirror_account (account_id),

    CONSTRAINT fk_mirror_account
        FOREIGN KEY (account_id)
        REFERENCES account(account_id)
        ON DELETE CASCADE
);


-- ============================================================
-- Optional message provenance for mirror delivery
--
-- This is NOT required to identify the message's destination;
-- it simply permits the server to know which mirror accepted it.
-- It does not replace sender_address or recipient addresses.
-- ============================================================

CREATE TABLE message_mirror (
    message_id BIGINT UNSIGNED PRIMARY KEY,
    mirror_id BIGINT UNSIGNED NOT NULL,

    CONSTRAINT fk_message_mirror_message
        FOREIGN KEY (message_id)
        REFERENCES message(message_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_message_mirror_mirror
        FOREIGN KEY (mirror_id)
        REFERENCES mirror(mirror_id)
        ON DELETE CASCADE
);