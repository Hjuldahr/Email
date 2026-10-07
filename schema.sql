DROP DATABASE IF EXISTS pearlescence;
CREATE DATABASE pearlescence
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

USE pearlescence;

CREATE TABLE account (
    account_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
    username VARCHAR(254) NOT NULL UNIQUE, 
    password_hash VARBINARY(512) NOT NULL, 
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), 
    last_login_at DATETIME(6) NULL
);

CREATE TABLE address (
    address_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
    account_id BIGINT UNSIGNED NOT NULL, 
    address VARCHAR(254) NOT NULL UNIQUE, 
    enabled BOOLEAN NOT NULL DEFAULT TRUE, 
    registered_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), 
    FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE 
);

CREATE TABLE address_reservation (
    reservation_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
    address VARCHAR(254) NOT NULL UNIQUE, 
    account_id BIGINT UNSIGNED NULL, 
    released_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), 
    reserved_until DATETIME(6) NOT NULL DEFAULT (CURRENT_TIMESTAMP(6) + INTERVAL 1 WEEK), 
    FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE SET NULL
);

CREATE TABLE contact (
    contact_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
    account_id BIGINT UNSIGNED NOT NULL, 
    name VARCHAR(255) NOT NULL, 
    address VARCHAR(254) NOT NULL, 
    about TEXT NULL, 
    added_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), 
    UNIQUE KEY (account_id, address), 
    FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE
);

CREATE TABLE block (
    block_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
    account_id BIGINT UNSIGNED NOT NULL, 
    address VARCHAR(254) NOT NULL, 
    blocked_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), 
    UNIQUE KEY (account_id, address),
    FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE
);

CREATE TABLE message (
    thread_id BIGINT UNSIGNED,
    message_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
    sender_address VARCHAR(254) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    subject TEXT NOT NULL,
    payload LONGTEXT NOT NULL
);

CREATE TABLE attachment (
    attachment_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
    message_id BIGINT UNSIGNED NOT NULL, 
    attachment_index INT UNSIGNED NOT NULL, 
    filename VARCHAR(255) NOT NULL, 
    content_type VARCHAR(255) NULL, 
    size_bytes BIGINT UNSIGNED NOT NULL, 
    payload LONGBLOB NOT NULL, 
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), 
    UNIQUE KEY (message_id, attachment_index),
    FOREIGN KEY (message_id) REFERENCES message(message_id) ON DELETE CASCADE
);

CREATE TABLE message_recipient (
    recipient_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
    account_id BIGINT UNSIGNED NULL, 
    message_id BIGINT UNSIGNED NOT NULL, 
    recipient_type ENUM('TO', 'CC', 'BCC') NOT NULL, 
    address VARCHAR(254) NOT NULL, 
    recipient_order INT UNSIGNED NOT NULL DEFAULT 0, 
    KEY (message_id, recipient_type, recipient_order), 
    UNIQUE KEY (message_id, recipient_type, address),
    FOREIGN KEY (message_id) REFERENCES message(message_id) ON DELETE CASCADE, 
    FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE
);

CREATE TABLE inbound_message (
    message_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    current_folder ENUM('INBOX','ARCHIVE','JUNK','TRASH','MERC') NOT NULL DEFAULT 'INBOX',
    original_folder ENUM('INBOX','ARCHIVE','JUNK','TRASH','MERC') NOT NULL DEFAULT 'INBOX',
    flagged BOOLEAN NOT NULL DEFAULT FALSE,
    seen BOOLEAN NOT NULL DEFAULT FALSE,
    received_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    read_at DATETIME(6) NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), 
    KEY (account_id, current_folder, message_id),
    PRIMARY KEY (account_id, message_id),
    FOREIGN KEY (message_id) REFERENCES message(message_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE
);

CREATE TABLE inbound_message_tag (
    message_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    tag VARCHAR(255) NOT NULL,
    PRIMARY KEY (account_id, message_id, tag),
    FOREIGN KEY (account_id, message_id) REFERENCES inbound_message(account_id, message_id) ON DELETE CASCADE
);

CREATE TABLE outbound_message (
    message_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    current_folder ENUM('DRAFTS','OUTBOX','SENT','TRASH','ARCHIVE') NOT NULL DEFAULT 'DRAFTS',
    original_folder ENUM('DRAFTS','OUTBOX','SENT','TRASH','ARCHIVE') NOT NULL DEFAULT 'DRAFTS',
    flagged BOOLEAN NOT NULL DEFAULT FALSE,
    drafted_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    out_at DATETIME(6) NULL,
    sent_at DATETIME(6) NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), 
    KEY (account_id, current_folder, message_id),
    PRIMARY KEY (account_id, message_id),
    FOREIGN KEY (message_id) REFERENCES message(message_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE
);

CREATE TABLE outbound_message_tag (
    message_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    tag VARCHAR(255) NOT NULL,
    PRIMARY KEY (account_id, message_id, tag),
    FOREIGN KEY (account_id, message_id) REFERENCES outbound_message(account_id, message_id) ON DELETE CASCADE
);

CREATE TABLE mirror (
    mirror_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
    account_id BIGINT UNSIGNED NOT NULL, 
    address VARCHAR(254) NOT NULL UNIQUE, 
    enabled BOOLEAN NOT NULL DEFAULT TRUE, 
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), 
    disabled_at DATETIME(6) NULL, 
    FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE
);

CREATE TABLE action (
    action_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, -- Protocol-visible Action UID. 
    action_uid BINARY(16) NOT NULL UNIQUE, 
    account_id BIGINT UNSIGNED NOT NULL, 
    enabled BOOLEAN NOT NULL DEFAULT TRUE, 
    priority INT NOT NULL, 
    filter JSON NOT NULL, 
    operations JSON NOT NULL, 
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), 
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), 
    FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE
);

SET GLOBAL event_scheduler = ON; 
DELIMITER $$ 

CREATE EVENT ev_cleanup 
ON SCHEDULE EVERY 1 DAY STARTS CURRENT_TIMESTAMP + INTERVAL 1 DAY 
DO BEGIN 
    DELETE ar FROM address_reservation ar 
    LEFT JOIN address a ON ar.address = a.address 
    WHERE ar.reserved_until < CURRENT_TIMESTAMP(6) OR a.address IS NOT NULL; 
    
    DELETE im FROM inbound_message AS im
    INNER JOIN message_recipient AS mr ON im.message_id = mr.message_id
    INNER JOIN mirror AS mir ON mr.address = mir.address
    WHERE NOT mir.enabled;

    DELETE FROM mirror 
    WHERE NOT enabled;
    
    UPDATE outbound_message SET original_folder = 'OUTBOX', current_folder = 'DRAFTS', out_at = NULL 
    WHERE out_at < CURRENT_TIMESTAMP(6) - INTERVAL 1 WEEK AND current_folder = 'OUTBOX'; 

    UPDATE outbound_message SET original_folder = 'SENT', current_folder = 'ARCHIVE' 
    WHERE sent_at < CURRENT_TIMESTAMP(6) - INTERVAL 2 MONTH AND current_folder = 'SENT'; 
    
    UPDATE inbound_message SET original_folder = 'INBOX', current_folder = 'ARCHIVE' 
    WHERE received_at < CURRENT_TIMESTAMP(6) - INTERVAL 6 MONTH AND current_folder = 'INBOX'; 
    
    UPDATE outbound_message SET original_folder = 'DRAFTS', current_folder = 'ARCHIVE' 
    WHERE drafted_at < CURRENT_TIMESTAMP(6) - INTERVAL 6 MONTH AND updated_at < CURRENT_TIMESTAMP(6) - INTERVAL 6 MONTH AND current_folder = 'DRAFTS'; 
    
    DELETE FROM outbound_message 
    WHERE current_folder = 'TRASH' AND updated_at < CURRENT_TIMESTAMP(6) - INTERVAL 2 MONTH; 
    
    DELETE FROM inbound_message 
    WHERE current_folder = 'TRASH' AND updated_at < CURRENT_TIMESTAMP(6) - INTERVAL 2 MONTH; 
    
    DELETE m FROM message AS m
    LEFT JOIN inbound_message AS im ON im.message_id = m.message_id
    LEFT JOIN outbound_message AS om ON om.message_id = m.message_id
    WHERE im.message_id IS NULL AND om.message_id IS NULL;

END$$ 

DELIMITER ;