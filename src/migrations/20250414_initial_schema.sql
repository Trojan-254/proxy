CREATE TABLE clients (
    client_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    tier VARCHAR(32) NOT NULL DEFAULT 'free',
    max_devices INT NOT NULL DEFAULT 3,
    active_devices INT NOT NULL DEFAULT 0,
    quota_daily INT NOT NULL DEFAULT 5000,
    quota_used INT NOT NULL DEFAULT 0,
    custom_rules_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE client_ip_mappings (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL REFERENCES clients(client_id),
    ip_address VARCHAR(45) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_active_ip_address ON client_ip_mappings (ip_address) WHERE active = TRUE;

CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL REFERENCES clients(client_id),
    device_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(32),
    browser_fingerprint VARCHAR(64),
    device_group VARCHAR(64),
    last_active TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(client_id, device_id)
);
CREATE INDEX idx_devices_last_active ON devices(client_id, last_active);

CREATE TABLE filtering_rules (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL REFERENCES clients(client_id),
    device_group VARCHAR(64),
    rule_type VARCHAR(32) NOT NULL,
    value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_filtering_rules_client ON filtering_rules(client_id, device_group);

CREATE TABLE time_restrictions (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL REFERENCES clients(client_id),
    name VARCHAR(255) NOT NULL,
    days VARCHAR(255) NOT NULL, -- Serialized array of days
    start_time VARCHAR(5) NOT NULL, -- Format: "HH:MM"
    end_time VARCHAR(5) NOT NULL, -- Format: "HH:MM"
    blocked_categories TEXT NOT NULL, -- Serialized array of categories
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_time_restrictions_client ON time_restrictions(client_id);

CREATE TABLE usage_logs (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL REFERENCES clients(client_id),
    device_id VARCHAR(64),
    log_date DATE NOT NULL DEFAULT CURRENT_DATE,
    request_count INT NOT NULL DEFAULT 0,
    blocked_count INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_usage_logs_daily ON usage_logs(client_id, device_id, log_date);