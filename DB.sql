CREATE TABLE wg_clients (
    client_id VARCHAR(64) PRIMARY KEY,

    -- identity
    name VARCHAR(100),

    -- wireguard config
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    address VARCHAR(45) NOT NULL,
    dns VARCHAR(100),
    allowed_ips VARCHAR(100),
    endpoint VARCHAR(255),

    status TINYINT(1) DEFAULT 1,

    --1 = Active
    --2 = Disabled
    --3 = Expired
    --4 = Suspended
    --5 = Pending
    --6 = Deleted

    -- timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- DB updated
    last_seen DATETIME NULL, --when client was active
    last_handshake DATETIME, --Latest WireGuard handshake

    -- ===== TRAFFIC TOTALS (PERSISTENT) =====
    rx_bytes BIGINT UNSIGNED DEFAULT 0,
    tx_bytes BIGINT UNSIGNED DEFAULT 0,
    total_bytes BIGINT UNSIGNED GENERATED ALWAYS AS (rx_bytes + tx_bytes) STORED,

    -- ===== SNAPSHOT FOR DELTA CALCULATION =====
    last_rx_snapshot BIGINT UNSIGNED DEFAULT 0,
    last_tx_snapshot BIGINT UNSIGNED DEFAULT 0,

    -- ===== OPTIONAL LIMIT CONTROL =====
    max_data_limit BIGINT UNSIGNED DEFAULT NULL,
    speed_limit_kbps INT DEFAULT NULL
);