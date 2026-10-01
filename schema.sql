DROP DATABASE IF EXISTS email_store;
CREATE DATABASE email_store;
USE email_store;

CREATE TABLE user_accounts (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(254) NOT NULL,
    user_password_hash VARBINARY(256) NOT NULL,
    created_on DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_accessed_on DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_addresses (
    address_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    address VARCHAR(254) NOT NULL UNIQUE,
    is_alias BOOL NOT NULL DEFAULT false,
    FOREIGN KEY (user_id)
        REFERENCES user_accounts(user_id)
        ON DELETE CASCADE
);

CREATE TABLE user_rules (
    rule_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    priority INT NOT NULL DEFAULT 0,
    rule TEXT NOT NULL,
    created_on DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)
        REFERENCES user_accounts(user_id)
        ON DELETE CASCADE
);

CREATE TABLE contacts (
    contact_id INT AUTO_INCREMENT PRIMARY KEY,
    contact_address VARCHAR(254) NOT NULL,
    contact_name VARCHAR(254) NOT NULL,
    user_id INT NOT NULL,
    UNIQUE (user_id, contact_address),
    created_on DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)
        REFERENCES user_accounts(user_id)
        ON DELETE CASCADE
);

CREATE TABLE messages (
    user_id INT NOT NULL,
    thread_id INT NOT NULL,
    message_id INT NOT NULL,
    parent_message_id INT NULL,
    from_address VARCHAR(254) NOT NULL,
    return_path VARCHAR(254) NOT NULL,
    subject_line VARCHAR(256) NOT NULL,
    sent_on DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    first_read_on DATETIME NULL,
    body TEXT NULL,
    body_size INT NOT NULL DEFAULT 0,
    dkim_signature VARCHAR(2048),
    is_read BOOL NOT NULL DEFAULT false,
    is_flagged BOOL NOT NULL DEFAULT false,
    folder enum('Inbox', 'ASAP', 'ToDo', 'TBC', 'TBD', 'Memo', 'Spam', 'Junk', 'Archived', 'Draft', 'Outbox', 'Sent') NOT NULL DEFAULT 'Inbox',
    PRIMARY KEY (message_id),
    FOREIGN KEY (user_id)
        REFERENCES user_accounts(user_id)
        ON DELETE CASCADE,
    FOREIGN KEY (parent_message_id)
        REFERENCES messages(message_id)
);

CREATE TABLE message_recipients (
    message_id INT NOT NULL,
    to_address VARCHAR(254) NOT NULL,
    type ENUM('To', 'Cc', 'Bcc') NOT NULL DEFAULT 'To',
    PRIMARY KEY (message_id, to_address),
    FOREIGN KEY (message_id)
        REFERENCES messages(message_id)
        ON DELETE CASCADE
);

CREATE TABLE tags (
    tag_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    tag_name VARCHAR(50) NOT NULL,
    UNIQUE (user_id, tag_name),
    FOREIGN KEY (user_id)
        REFERENCES user_accounts(user_id)
        ON DELETE CASCADE
);

CREATE TABLE email_tags (
    tag_id INT NOT NULL,
    message_id INT NOT NULL,
    PRIMARY KEY (tag_id, message_id),
    FOREIGN KEY (tag_id)
        REFERENCES tags(tag_id)
        ON DELETE CASCADE,
    FOREIGN KEY (message_id)
        REFERENCES messages(message_id)
        ON DELETE CASCADE
);

CREATE TABLE attachments (
    attachment_id INT AUTO_INCREMENT PRIMARY KEY,
    message_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    content_type VARCHAR(100) NOT NULL,
    file_size INT NOT NULL,
    storage_path VARCHAR(2048) NOT NULL,
    FOREIGN KEY (message_id)
        REFERENCES messages(message_id)
        ON DELETE CASCADE
);