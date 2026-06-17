
CREATE TABLE accounts (
    UserID INT PRIMARY KEY,  -- Telegram ID
    FirstName VARCHAR(50),
    LastName VARCHAR(50),
    Username VARCHAR(50),
    CurrentBalance DECIMAL(10,2) DEFAULT 0.00,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE wg_clients (

    -- Unique client record ID
    client_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    -- Owner account (Telegram / website / admin) - optional
    UserID BIGINT UNSIGNED NULL,

    -- Human-readable client name
    name VARCHAR(100) NOT NULL,

    -- Optional client description
    description TEXT NULL,

    -- WireGuard server hosting this client
    server_name VARCHAR(100) NOT NULL,

    -- Client private key (optional storage)
    private_key TEXT NULL,

    -- Client public key (WireGuard peer identifier)
    public_key VARCHAR(44) NOT NULL UNIQUE,

    -- Assigned VPN IP address
    address VARCHAR(45) NOT NULL UNIQUE,

    -- DNS servers pushed to client
    dns VARCHAR(255) NULL,

    -- Allowed IP routes for client
    allowed_ips VARCHAR(255) NOT NULL,

    -- Remote endpoint if applicable
    endpoint VARCHAR(255) NULL,

    -- Client enabled/disabled status
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Subscription expiration flag
    is_expired BOOLEAN NOT NULL DEFAULT FALSE,

    -- Administrative suspension flag
    is_suspended BOOLEAN NOT NULL DEFAULT FALSE,

    -- Soft-delete flag
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,

    -- Record creation timestamp
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    -- Last record modification timestamp
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
        ON UPDATE CURRENT_TIMESTAMP(3),

    -- Last successful WireGuard handshake
    last_handshake DATETIME(3) NULL,

    -- Subscription expiration date/time
    expires_at DATETIME(3) NULL,

    -- Last successful traffic collector poll
    last_poll_at DATETIME(3) NULL,

    -- Persistent cumulative download traffic
    rx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,

    -- Persistent cumulative upload traffic
    tx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,

    -- Total cumulative traffic (RX + TX)
    total_bytes BIGINT UNSIGNED
        GENERATED ALWAYS AS (rx_bytes + tx_bytes) STORED,

    -- Last observed WireGuard RX counter
    last_rx_snapshot BIGINT UNSIGNED NOT NULL DEFAULT 0,

    -- Last observed WireGuard TX counter
    last_tx_snapshot BIGINT UNSIGNED NOT NULL DEFAULT 0,

    -- Maximum allowed traffic quota in bytes
    max_data_limit BIGINT UNSIGNED NULL
        COMMENT 'Maximum bytes allowed, NULL = unlimited',

    -- Traffic shaping limit in kbps
    speed_limit_kbps INT UNSIGNED NULL
        COMMENT 'Speed limit in kbps, NULL = unlimited',

    -- Administrator/system that created the client
    created_by VARCHAR(64) NULL,

    -- Internal notes
    notes TEXT NULL,

    -- Fast lookup by owner (Telegram/website/admin)
    INDEX idx_user (UserID),

    -- Fast lookup user keys per server
    INDEX idx_user_server (UserID, server_name),

    -- Fast lookup clients by server
    INDEX idx_server (server_name),

    -- Fast lookup active clients per server
    INDEX idx_server_active (server_name, is_active),

    -- Fast lookup valid clients per server
    INDEX idx_server_status (
        server_name,
        is_active,
        is_expired,
        is_suspended,
        is_deleted
    ),

    -- Fast lookup expiring clients
    INDEX idx_expires (expires_at),

    -- Fast lookup handshake status
    INDEX idx_last_handshake (last_handshake),

    -- Monitor collector health
    INDEX idx_last_poll (last_poll_at),

    -- Foreign key (optional owner link)
    CONSTRAINT fk_wg_clients_user
        FOREIGN KEY (UserID)
        REFERENCES accounts(UserID)
        ON DELETE CASCADE

) ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;
