CREATE TABLE wireguard_peers (
    PeerID          INT AUTO_INCREMENT PRIMARY KEY,

    UserID          BIGINT NOT NULL COMMENT 'Telegram user ID — globally unique identifier from Bot API',

    ServerName      VARCHAR(100) NOT NULL COMMENT 'friendly server identifier, e.g. "Tokyo-1", "Frankfurt-HighSpeed"',

    Name            VARCHAR(80) NOT NULL DEFAULT '' COMMENT 'custom/friendly name, e.g. "iPhone 15", "Work Laptop - Dubai", "Trial User #42"',

    PublicKey       CHAR(44) NOT NULL UNIQUE COMMENT 'peer public key (server-side view)',
    PrivateKey      CHAR(44) NOT NULL COMMENT 'peer private key (delivered to client in config)',
    PresharedKey    CHAR(44) DEFAULT NULL COMMENT 'optional pre-shared key',

    AllowedIPs      VARCHAR(512) NOT NULL COMMENT 'comma-separated, e.g. "10.55.0.5/32, fd42::5/128"',

    DataLimitBytes  BIGINT DEFAULT NULL COMMENT 'NULL = unlimited',
    RxBytes         BIGINT NOT NULL DEFAULT 0 COMMENT 'bytes received by peer (download from server perspective)',
    TxBytes         BIGINT NOT NULL DEFAULT 0 COMMENT 'bytes sent by peer (upload from server perspective)',

    IssuedAt        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ValidDays       SMALLINT NOT NULL DEFAULT 30 COMMENT 'validity period in days',

    IsActive        BOOLEAN NOT NULL DEFAULT TRUE,
    DeactivatedAt   DATETIME DEFAULT NULL COMMENT 'timestamp when access was revoked',

    LastHandshakeAt DATETIME DEFAULT NULL COMMENT 'last successful handshake (from wg show)',
    HandshakeStatus TINYINT NOT NULL DEFAULT 0 
        COMMENT '0=never connected, 1=definitely online, 2=probably online, 3=offline',

    FOREIGN KEY (UserID) REFERENCES accounts(UserID) ON DELETE CASCADE,

    -- Recommended indexes
    INDEX idx_user_active (UserID, IsActive),
    INDEX idx_pubkey (PublicKey)  -- redundant with UNIQUE but explicit
    -- Optional: INDEX idx_status (IsActive, HandshakeStatus, ValidDays)
);
