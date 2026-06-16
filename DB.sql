CREATE TABLE wg_clients (
    client_id VARCHAR(64) PRIMARY KEY,

    -- identity
    name VARCHAR(100),

    -- wireguard config
    private_key TEXT NOT NULL,
    public_key VARCHAR(44) NOT NULL UNIQUE,
    address VARCHAR(45) NOT NULL UNIQUE,
    dns VARCHAR(255),
    allowed_ips VARCHAR(255),
    endpoint VARCHAR(255),

    -- status
    status TINYINT UNSIGNED NOT NULL DEFAULT 1,

    -- 1 = Active
    -- 2 = Disabled
    -- 3 = Expired
    -- 4 = Suspended
    -- 5 = Pending
    -- 6 = Deleted

    -- timestamps
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    last_seen DATETIME NULL,
    last_handshake DATETIME NULL,

    -- persistent traffic totals
    rx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
    tx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
    total_bytes BIGINT UNSIGNED
        GENERATED ALWAYS AS (rx_bytes + tx_bytes) STORED,

    -- snapshot values from latest wg poll
    last_rx_snapshot BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_tx_snapshot BIGINT UNSIGNED NOT NULL DEFAULT 0,

    -- limits
    max_data_limit BIGINT UNSIGNED NULL,
    speed_limit_kbps INT UNSIGNED NULL,

    INDEX idx_status (status),
    INDEX idx_last_seen (last_seen),
    INDEX idx_last_handshake (last_handshake)
);