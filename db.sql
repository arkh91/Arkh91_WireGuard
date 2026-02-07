CREATE TABLE accounts (
    UserID          BIGINT PRIMARY KEY COMMENT 'Telegram User ID (64-bit)',
    FirstName       VARCHAR(50),
    LastName        VARCHAR(50),
    Username        VARCHAR(50),
    CurrentBalance  DECIMAL(10,2) DEFAULT 0.00,
    CreatedAt       DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- Add if needed later:
    -- MaxDevices      TINYINT UNSIGNED DEFAULT 1 COMMENT 'max active peers allowed'
);

CREATE TABLE wireguard_peers (
    PeerID          INT AUTO_INCREMENT PRIMARY KEY,

    UserID          BIGINT NOT NULL COMMENT 'Telegram user ID — links to accounts',

    PurchaseGroup   SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    DeviceSeq       TINYINT UNSIGNED NOT NULL DEFAULT 1,
    DisplaySlot     VARCHAR(16) GENERATED ALWAYS AS (CONCAT(DeviceSeq, '-', PurchaseGroup)) STORED 
        COMMENT 'e.g. "1-2", "2-2", "1-3"',

    ServerName      VARCHAR(100) NOT NULL,
    Name            VARCHAR(80) NOT NULL DEFAULT '',

    PublicKey       CHAR(44) NOT NULL UNIQUE,
    PrivateKey      CHAR(44) NOT NULL,
    PresharedKey    CHAR(44) DEFAULT NULL,

    AllowedIPs      VARCHAR(512) NOT NULL,

    DataLimitBytes  BIGINT DEFAULT NULL COMMENT 'NULL = unlimited',
    RxBytes         BIGINT NOT NULL DEFAULT 0,
    TxBytes         BIGINT NOT NULL DEFAULT 0,

    IssuedAt        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ValidDays       SMALLINT NOT NULL DEFAULT 30,

    IsActive        BOOLEAN NOT NULL DEFAULT TRUE,
    DeactivatedAt   DATETIME DEFAULT NULL,

    LastHandshakeAt DATETIME DEFAULT NULL,
    HandshakeStatus TINYINT NOT NULL DEFAULT 0 
        COMMENT '0=never connected, 1=definitely online, 2=probably online, 3=offline',

    FOREIGN KEY (UserID) REFERENCES accounts(UserID) ON DELETE CASCADE,

    UNIQUE KEY uk_user_group_seq (UserID, PurchaseGroup, DeviceSeq),
    INDEX idx_user_active (UserID, IsActive),
    INDEX idx_pubkey (PublicKey)
);
