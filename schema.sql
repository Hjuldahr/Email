DROP DATABASE IF EXISTS pearlescence;
CREATE DATABASE pearlescence;
USE pearlescence;

-- ============================================================
-- Accounts / Addresses
-- ============================================================

CREATE TABLE accounts (
    account_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    base_address VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARBINARY(256) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_login_at DATETIME(6) NULL
);

CREATE TABLE addresses (
    address_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    address VARCHAR(254) NOT NULL UNIQUE,
    is_alias BOOLEAN NOT NULL DEFAULT FALSE,

    FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE
);

-- ============================================================
-- Folders
-- ============================================================

CREATE TABLE folders (
    folder_id TINYINT UNSIGNED PRIMARY KEY,
    name VARCHAR(16) NOT NULL UNIQUE
);

INSERT INTO folders (folder_id, name) VALUES
    (1, 'INBOX'),
    (2, 'OUTBOX'),
    (3, 'DRAFTS'),
    (4, 'SENT'),
    (5, 'TRASH'),
    (6, 'JUNK'),
    (7, 'SPAM'),
    (8, 'MERC');

-- ============================================================
-- Threads
-- ============================================================

CREATE TABLE threads (
    thread_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE
);

-- ============================================================
-- Messages
-- ============================================================

CREATE TABLE messages (
    message_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    thread_id BIGINT UNSIGNED NULL,
    folder_id TINYINT UNSIGNED NOT NULL,

    sender_address VARCHAR(254) NOT NULL,
    subject VARCHAR(998) NOT NULL,
    body MEDIUMBLOB NOT NULL,

    flagged BOOLEAN NOT NULL DEFAULT FALSE,
    seen BOOLEAN NOT NULL DEFAULT FALSE,

    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    received_at DATETIME(6) NULL,
    sent_at DATETIME(6) NULL,
    seen_at DATETIME(6) NULL,

    FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE,

    FOREIGN KEY (thread_id)
        REFERENCES threads(thread_id)
        ON DELETE SET NULL,

    FOREIGN KEY (folder_id)
        REFERENCES folders(folder_id),

    INDEX idx_messages_account_folder (account_id, folder_id),
    INDEX idx_messages_thread (thread_id),
    INDEX idx_messages_send_time (account_id, created_at),
    INDEX idx_messages_sender (account_id, sender_address)
);

-- ============================================================
-- Message Recipients
-- ============================================================

CREATE TABLE message_recipients (
    message_id BIGINT UNSIGNED NOT NULL,
    recipient_address VARCHAR(254) NOT NULL,
    recipient_type ENUM('TO', 'CC', 'BCC') NOT NULL,

    PRIMARY KEY (message_id, recipient_address, recipient_type),

    FOREIGN KEY (message_id)
        REFERENCES messages(message_id)
        ON DELETE CASCADE,

    INDEX idx_recipients_address (recipient_address)
);

-- ============================================================
-- Tags
-- ============================================================

CREATE TABLE tags (
    tag_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE,

    UNIQUE KEY uq_account_tag (account_id, name)
);

CREATE TABLE message_tags (
    message_id BIGINT UNSIGNED NOT NULL,
    tag_id BIGINT UNSIGNED NOT NULL,

    PRIMARY KEY (message_id, tag_id),

    FOREIGN KEY (message_id)
        REFERENCES messages(message_id)
        ON DELETE CASCADE,

    FOREIGN KEY (tag_id)
        REFERENCES tags(tag_id)
        ON DELETE CASCADE
);

-- ============================================================
-- Attachments
-- ============================================================

CREATE TABLE attachments (
    attachment_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    message_id BIGINT UNSIGNED NOT NULL,
    attachment_index INT UNSIGNED NOT NULL,

    filename VARCHAR(255) NOT NULL,
    content_type VARCHAR(255) NULL,
    file_size BIGINT UNSIGNED NOT NULL,
    payload LONGBLOB NOT NULL,

    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    FOREIGN KEY (message_id)
        REFERENCES messages(message_id)
        ON DELETE CASCADE,

    UNIQUE KEY uq_attachment_index (message_id, attachment_index)
);

-- ============================================================
-- Contacts
-- ============================================================

CREATE TABLE contacts (
    contact_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    about TEXT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE
);

CREATE TABLE contact_addresses (
    contact_id BIGINT UNSIGNED NOT NULL,
    address VARCHAR(254) NOT NULL,

    PRIMARY KEY (contact_id, address),

    FOREIGN KEY (contact_id)
        REFERENCES contacts(contact_id)
        ON DELETE CASCADE,

    UNIQUE KEY uq_contact_address (address)
);

-- ============================================================
-- Block List
-- ============================================================

CREATE TABLE blocked_addresses (
    block_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    address VARCHAR(254) NOT NULL,
    blocked_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE,

    UNIQUE KEY uq_blocked_address (account_id, address)
);

-- ============================================================
-- Mirror Addresses
-- ============================================================

CREATE TABLE mirrors (
    mirror_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    address VARCHAR(254) NOT NULL UNIQUE,

    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    disabled_at DATETIME(6) NULL,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE,

    INDEX idx_mirrors_account_active (account_id, active)
);

-- ============================================================
-- Actions
-- ============================================================

CREATE TABLE actions (
    action_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,

    priority INT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE,

    INDEX idx_actions_account_priority (account_id, priority)
);

-- Action filter
CREATE TABLE action_filters (
    action_id BIGINT UNSIGNED PRIMARY KEY,

    send_after DATETIME(6) NULL,
    send_before DATETIME(6) NULL,

    subject_pattern VARCHAR(998) NULL,

    FOREIGN KEY (action_id)
        REFERENCES actions(action_id)
        ON DELETE CASCADE
);

CREATE TABLE action_filter_addresses (
    action_id BIGINT UNSIGNED NOT NULL,
    address VARCHAR(254) NOT NULL,
    direction ENUM('FROM', 'TO', 'CC') NOT NULL,
    mode ENUM('WHITELIST', 'BLACKLIST') NOT NULL,

    PRIMARY KEY (action_id, address, direction, mode),

    FOREIGN KEY (action_id)
        REFERENCES actions(action_id)
        ON DELETE CASCADE
);

CREATE TABLE action_filter_tags (
    action_id BIGINT UNSIGNED NOT NULL,
    tag_pattern VARCHAR(255) NOT NULL,
    mode ENUM('WHITELIST', 'BLACKLIST') NOT NULL,

    PRIMARY KEY (action_id, tag_pattern, mode),

    FOREIGN KEY (action_id)
        REFERENCES actions(action_id)
        ON DELETE CASCADE
);

-- ============================================================
-- Action Operations
-- ============================================================

CREATE TABLE action_operations (
    operation_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    action_id BIGINT UNSIGNED NOT NULL,

    operation_index INT UNSIGNED NOT NULL,
    operation_type ENUM(
        'FLAG',
        'SEEN',
        'TAG',
        'DELETE',
        'ARCH',
        'REPLY',
        'DOWN',
        'DETACH'
    ) NOT NULL,

    argument VARCHAR(998) NULL,

    FOREIGN KEY (action_id)
        REFERENCES actions(action_id)
        ON DELETE CASCADE,

    UNIQUE KEY uq_action_operation_order
        (action_id, operation_index)
);

-- ============================================================
-- Message State / Movement History
-- ============================================================

CREATE TABLE message_folder_history (
    history_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    message_id BIGINT UNSIGNED NOT NULL,

    from_folder_id TINYINT UNSIGNED NULL,
    to_folder_id TINYINT UNSIGNED NOT NULL,

    changed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    FOREIGN KEY (message_id)
        REFERENCES messages(message_id)
        ON DELETE CASCADE,

    FOREIGN KEY (from_folder_id)
        REFERENCES folders(folder_id),

    FOREIGN KEY (to_folder_id)
        REFERENCES folders(folder_id),

    INDEX idx_folder_history_message (message_id, changed_at)
);