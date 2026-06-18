
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

CREATE TABLE vpn_servers (
    ServerID INT AUTO_INCREMENT PRIMARY KEY,

    ServerName VARCHAR(50) NOT NULL,     -- IR-Tehran-1, UK-London-1
    Country VARCHAR(50) NOT NULL,
    City VARCHAR(50) NOT NULL,

    -- Routing endpoints
    PublicURLInternational VARCHAR(255) NOT NULL,
    PublicURLIran VARCHAR(255) NOT NULL,

    -- Network ports (separated clearly)
    WireGuardPort INT DEFAULT 51820,
    OutlinePort INT DEFAULT NULL,

    -- Server address
    IPAddress VARCHAR(45),

    -- Security
    APIKey VARCHAR(255),
    BearerToken VARCHAR(255),

    -- Capacity
    MaxUsers INT DEFAULT 0,
    CurrentUsers INT DEFAULT 0,

    -- Operational state
    Status ENUM('ACTIVE','INACTIVE','MAINTENANCE','FULL') DEFAULT 'ACTIVE',

    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    INDEX idx_country (Country),
    INDEX idx_city (City),
    INDEX idx_status (Status),
    INDEX idx_status_country (Status, Country)
);

CREATE TABLE countries (
    CountryID INT AUTO_INCREMENT PRIMARY KEY,

    CountryName VARCHAR(100) NOT NULL,

    CountryCode CHAR(2) NOT NULL UNIQUE,   -- US, IR, DE

    FlagEmoji VARCHAR(10),
    FlagURL VARCHAR(255),

    Continent VARCHAR(50),

    IsActive BOOLEAN DEFAULT TRUE,

    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_country_code (CountryCode)
);
INSERT INTO countries (CountryName, CountryCode, FlagEmoji, Continent)
VALUES
('Afghanistan', 'AF', '🇦🇫', 'Asia'),
('Albania', 'AL', '🇦🇱', 'Europe'),
('Algeria', 'DZ', '🇩🇿', 'Africa'),
('Andorra', 'AD', '🇦🇩', 'Europe'),
('Angola', 'AO', '🇦🇴', 'Africa'),
('Argentina', 'AR', '🇦🇷', 'South America'),
('Armenia', 'AM', '🇦🇲', 'Asia'),
('Australia', 'AU', '🇦🇺', 'Oceania'),
('Austria', 'AT', '🇦🇹', 'Europe'),
('Azerbaijan', 'AZ', '🇦🇿', 'Asia'),

('Bahamas', 'BS', '🇧🇸', 'North America'),
('Bahrain', 'BH', '🇧🇭', 'Asia'),
('Bangladesh', 'BD', '🇧🇩', 'Asia'),
('Barbados', 'BB', '🇧🇧', 'North America'),
('Belarus', 'BY', '🇧🇾', 'Europe'),
('Belgium', 'BE', '🇧🇪', 'Europe'),
('Belize', 'BZ', '🇧🇿', 'North America'),
('Benin', 'BJ', '🇧🇯', 'Africa'),
('Bhutan', 'BT', '🇧🇹', 'Asia'),
('Bolivia', 'BO', '🇧🇴', 'South America'),
('Bosnia and Herzegovina', 'BA', '🇧🇦', 'Europe'),
('Botswana', 'BW', '🇧🇼', 'Africa'),
('Brazil', 'BR', '🇧🇷', 'South America'),
('Brunei', 'BN', '🇧🇳', 'Asia'),
('Bulgaria', 'BG', '🇧🇬', 'Europe'),
('Burkina Faso', 'BF', '🇧🇫', 'Africa'),
('Burundi', 'BI', '🇧🇮', 'Africa'),

('Cambodia', 'KH', '🇰🇭', 'Asia'),
('Cameroon', 'CM', '🇨🇲', 'Africa'),
('Canada', 'CA', '🇨🇦', 'North America'),
('Cape Verde', 'CV', '🇨🇻', 'Africa'),
('Central African Republic', 'CF', '🇨🇫', 'Africa'),
('Chad', 'TD', '🇹🇩', 'Africa'),
('Chile', 'CL', '🇨🇱', 'South America'),
('China', 'CN', '🇨🇳', 'Asia'),
('Colombia', 'CO', '🇨🇴', 'South America'),
('Comoros', 'KM', '🇰🇲', 'Africa'),
('Congo', 'CG', '🇨🇬', 'Africa'),
('Costa Rica', 'CR', '🇨🇷', 'North America'),
('Croatia', 'HR', '🇭🇷', 'Europe'),
('Cuba', 'CU', '🇨🇺', 'North America'),
('Cyprus', 'CY', '🇨🇾', 'Asia'),
('Czechia', 'CZ', '🇨🇿', 'Europe'),

('Democratic Republic of the Congo', 'CD', '🇨🇩', 'Africa'),
('Denmark', 'DK', '🇩🇰', 'Europe'),
('Djibouti', 'DJ', '🇩🇯', 'Africa'),
('Dominica', 'DM', '🇩🇲', 'North America'),
('Dominican Republic', 'DO', '🇩🇴', 'North America'),

('Ecuador', 'EC', '🇪🇨', 'South America'),
('Egypt', 'EG', '🇪🇬', 'Africa'),
('El Salvador', 'SV', '🇸🇻', 'North America'),
('Equatorial Guinea', 'GQ', '🇬🇶', 'Africa'),
('Eritrea', 'ER', '🇪🇷', 'Africa'),
('Estonia', 'EE', '🇪🇪', 'Europe'),
('Eswatini', 'SZ', '🇸🇿', 'Africa'),
('Ethiopia', 'ET', '🇪🇹', 'Africa'),

('Fiji', 'FJ', '🇫🇯', 'Oceania'),
('Finland', 'FI', '🇫🇮', 'Europe'),
('France', 'FR', '🇫🇷', 'Europe'),

('Gabon', 'GA', '🇬🇦', 'Africa'),
('Gambia', 'GM', '🇬🇲', 'Africa'),
('Georgia', 'GE', '🇬🇪', 'Asia'),
('Germany', 'DE', '🇩🇪', 'Europe'),
('Ghana', 'GH', '🇬🇭', 'Africa'),
('Greece', 'GR', '🇬🇷', 'Europe'),
('Grenada', 'GD', '🇬🇩', 'North America'),
('Guatemala', 'GT', '🇬🇹', 'North America'),
('Guinea', 'GN', '🇬🇳', 'Africa'),
('Guinea-Bissau', 'GW', '🇬🇼', 'Africa'),
('Guyana', 'GY', '🇬🇾', 'South America'),

('Haiti', 'HT', '🇭🇹', 'North America'),
('Honduras', 'HN', '🇭🇳', 'North America'),
('Hungary', 'HU', '🇭🇺', 'Europe'),

('Iceland', 'IS', '🇮🇸', 'Europe'),
('India', 'IN', '🇮🇳', 'Asia'),
('Indonesia', 'ID', '🇮🇩', 'Asia'),
('Iran', 'IR', '🇮🇷', 'Asia'),
('Iraq', 'IQ', '🇮🇶', 'Asia'),
('Ireland', 'IE', '🇮🇪', 'Europe'),
('Israel', 'IL', '🇮🇱', 'Asia'),
('Italy', 'IT', '🇮🇹', 'Europe'),

('Jamaica', 'JM', '🇯🇲', 'North America'),
('Japan', 'JP', '🇯🇵', 'Asia'),
('Jordan', 'JO', '🇯🇴', 'Asia'),

('Kazakhstan', 'KZ', '🇰🇿', 'Asia'),
('Kenya', 'KE', '🇰🇪', 'Africa'),
('Kiribati', 'KI', '🇰🇮', 'Oceania'),
('Kuwait', 'KW', '🇰🇼', 'Asia'),
('Kyrgyzstan', 'KG', '🇰🇬', 'Asia'),

('Laos', 'LA', '🇱🇦', 'Asia'),
('Latvia', 'LV', '🇱🇻', 'Europe'),
('Lebanon', 'LB', '🇱🇧', 'Asia'),
('Lesotho', 'LS', '🇱🇸', 'Africa'),
('Liberia', 'LR', '🇱🇷', 'Africa'),
('Libya', 'LY', '🇱🇾', 'Africa'),
('Liechtenstein', 'LI', '🇱🇮', 'Europe'),
('Lithuania', 'LT', '🇱🇹', 'Europe'),
('Luxembourg', 'LU', '🇱🇺', 'Europe'),

('Madagascar', 'MG', '🇲🇬', 'Africa'),
('Malawi', 'MW', '🇲🇼', 'Africa'),
('Malaysia', 'MY', '🇲🇾', 'Asia'),
('Maldives', 'MV', '🇲🇻', 'Asia'),
('Mali', 'ML', '🇲🇱', 'Africa'),
('Malta', 'MT', '🇲🇹', 'Europe'),
('Marshall Islands', 'MH', '🇲🇭', 'Oceania'),
('Mauritania', 'MR', '🇲🇷', 'Africa'),
('Mauritius', 'MU', '🇲🇺', 'Africa'),
('Mexico', 'MX', '🇲🇽', 'North America'),
('Micronesia', 'FM', '🇫🇲', 'Oceania'),
('Moldova', 'MD', '🇲🇩', 'Europe'),
('Monaco', 'MC', '🇲🇨', 'Europe'),
('Mongolia', 'MN', '🇲🇳', 'Asia'),
('Montenegro', 'ME', '🇲🇪', 'Europe'),
('Morocco', 'MA', '🇲🇦', 'Africa'),
('Mozambique', 'MZ', '🇲🇿', 'Africa'),
('Myanmar', 'MM', '🇲🇲', 'Asia'),

('Namibia', 'NA', '🇳🇦', 'Africa'),
('Nauru', 'NR', '🇳🇷', 'Oceania'),
('Nepal', 'NP', '🇳🇵', 'Asia'),
('Netherlands', 'NL', '🇳🇱', 'Europe'),
('New Zealand', 'NZ', '🇳🇿', 'Oceania'),
('Nicaragua', 'NI', '🇳🇮', 'North America'),
('Niger', 'NE', '🇳🇪', 'Africa'),
('Nigeria', 'NG', '🇳🇬', 'Africa'),
('North Korea', 'KP', '🇰🇵', 'Asia'),
('North Macedonia', 'MK', '🇲🇰', 'Europe'),
('Norway', 'NO', '🇳🇴', 'Europe'),

('Oman', 'OM', '🇴🇲', 'Asia'),

('Pakistan', 'PK', '🇵🇰', 'Asia'),
('Palau', 'PW', '🇵🇼', 'Oceania'),
('Palestine', 'PS', '🇵🇸', 'Asia'),
('Panama', 'PA', '🇵🇦', 'North America'),
('Papua New Guinea', 'PG', '🇵🇬', 'Oceania'),
('Paraguay', 'PY', '🇵🇾', 'South America'),
('Peru', 'PE', '🇵🇪', 'South America'),
('Philippines', 'PH', '🇵🇭', 'Asia'),
('Poland', 'PL', '🇵🇱', 'Europe'),
('Portugal', 'PT', '🇵🇹', 'Europe'),

('Qatar', 'QA', '🇶🇦', 'Asia'),

('Romania', 'RO', '🇷🇴', 'Europe'),
('Russia', 'RU', '🇷🇺', 'Europe'),
('Rwanda', 'RW', '🇷🇼', 'Africa'),

('Saint Kitts and Nevis', 'KN', '🇰🇳', 'North America'),
('Saint Lucia', 'LC', '🇱🇨', 'North America'),
('Saint Vincent and the Grenadines', 'VC', '🇻🇨', 'North America'),
('Samoa', 'WS', '🇼🇸', 'Oceania'),
('San Marino', 'SM', '🇸🇲', 'Europe'),
('Sao Tome and Principe', 'ST', '🇸🇹', 'Africa'),
('Saudi Arabia', 'SA', '🇸🇦', 'Asia'),
('Senegal', 'SN', '🇸🇳', 'Africa'),
('Serbia', 'RS', '🇷🇸', 'Europe'),
('Seychelles', 'SC', '🇸🇨', 'Africa'),
('Sierra Leone', 'SL', '🇸🇱', 'Africa'),
('Singapore', 'SG', '🇸🇬', 'Asia'),
('Slovakia', 'SK', '🇸🇰', 'Europe'),
('Slovenia', 'SI', '🇸🇮', 'Europe'),
('Solomon Islands', 'SB', '🇸🇧', 'Oceania'),
('Somalia', 'SO', '🇸🇴', 'Africa'),
('South Africa', 'ZA', '🇿🇦', 'Africa'),
('South Korea', 'KR', '🇰🇷', 'Asia'),
('South Sudan', 'SS', '🇸🇸', 'Africa'),
('Spain', 'ES', '🇪🇸', 'Europe'),
('Sri Lanka', 'LK', '🇱🇰', 'Asia'),
('Sudan', 'SD', '🇸🇩', 'Africa'),
('Suriname', 'SR', '🇸🇷', 'South America'),
('Sweden', 'SE', '🇸🇪', 'Europe'),
('Switzerland', 'CH', '🇨🇭', 'Europe'),
('Syria', 'SY', '🇸🇾', 'Asia'),

('Tajikistan', 'TJ', '🇹🇯', 'Asia'),
('Tanzania', 'TZ', '🇹🇿', 'Africa'),
('Thailand', 'TH', '🇹🇭', 'Asia'),
('Timor-Leste', 'TL', '🇹🇱', 'Asia'),
('Togo', 'TG', '🇹🇬', 'Africa'),
('Tonga', 'TO', '🇹🇴', 'Oceania'),
('Trinidad and Tobago', 'TT', '🇹🇹', 'North America'),
('Tunisia', 'TN', '🇹🇳', 'Africa'),
('Turkey', 'TR', '🇹🇷', 'Asia'),
('Turkmenistan', 'TM', '🇹🇲', 'Asia'),
('Tuvalu', 'TV', '🇹🇻', 'Oceania'),

('Uganda', 'UG', '🇺🇬', 'Africa'),
('Ukraine', 'UA', '🇺🇦', 'Europe'),
('United Arab Emirates', 'AE', '🇦🇪', 'Asia'),
('United Kingdom', 'GB', '🇬🇧', 'Europe'),
('United States', 'US', '🇺🇸', 'North America'),
('Uruguay', 'UY', '🇺🇾', 'South America'),
('Uzbekistan', 'UZ', '🇺🇿', 'Asia'),

('Vanuatu', 'VU', '🇻🇺', 'Oceania'),
('Vatican City', 'VA', '🇻🇦', 'Europe'),
('Venezuela', 'VE', '🇻🇪', 'South America'),
('Vietnam', 'VN', '🇻🇳', 'Asia'),

('Yemen', 'YE', '🇾🇪', 'Asia'),

('Zambia', 'ZM', '🇿🇲', 'Africa'),
('Zimbabwe', 'ZW', '🇿🇼', 'Africa');
