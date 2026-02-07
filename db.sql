CREATE TABLE wireguard_peers (
    PeerID          INT AUTO_INCREMENT PRIMARY KEY,

    UserID          INT NOT NULL,
    ServerID        INT NOT NULL,

    Name            VARCHAR(80) NOT NULL DEFAULT '' COMMENT 'custom/friendly name, e.g. "iPhone 15", "Work Laptop - Dubai", "Trial User #42"',

    PublicKey       CHAR(44) NOT NULL UNIQUE,           -- server's view: this peer's public key
    PrivateKey      CHAR(44) NOT NULL,                  -- client's private key (for generating full config) — usually NOT NULL
    PresharedKey    CHAR(44) DEFAULT NULL,              -- optional PSK

    AllowedIPs      VARCHAR(512) NOT NULL,              -- "10.55.0.5/32, fd42::5/128" etc.

    DataLimitBytes  BIGINT DEFAULT NULL COMMENT 'NULL = unlimited',
    RxBytes         BIGINT NOT NULL DEFAULT 0 COMMENT 'bytes received by the peer (download from server view)',
    TxBytes         BIGINT NOT NULL DEFAULT 0 COMMENT 'bytes sent by the peer (upload from server view)',

    IssuedAt        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ValidDays       SMALLINT NOT NULL DEFAULT 30,       -- required as per your bot

    IsActive        BOOLEAN NOT NULL DEFAULT TRUE,
    DeactivatedAt   DATETIME DEFAULT NULL COMMENT 'when access was revoked',

    LastHandshakeAt DATETIME DEFAULT NULL COMMENT 'last successful handshake time (from wg show)',
    HandshakeStatus TINYINT NOT NULL DEFAULT 0 
        COMMENT '0=never connected, 1=definitely online, 2=probably online, 3=offline',

    FOREIGN KEY (UserID) REFERENCES accounts(UserID) ON DELETE CASCADE
    -- FOREIGN KEY (ServerID) REFERENCES servers(ServerID) ON DELETE RESTRICT -- optional
);
