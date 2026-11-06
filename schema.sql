-- ========================================================
-- Fraud Detection & IP Risk Analysis Dashboard - Database Schema
-- Compatible with MySQL 5.7+ / 8.0+ and MariaDB
-- ========================================================

CREATE DATABASE IF NOT EXISTS fraud_detection_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE fraud_detection_db;

-- 1. IP Analysis Records Table
CREATE TABLE IF NOT EXISTS ip_analyses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    ip_version VARCHAR(10) NOT NULL DEFAULT 'IPv4',
    risk_score INT NOT NULL DEFAULT 0,
    risk_level ENUM('LOW', 'MEDIUM', 'HIGH') NOT NULL DEFAULT 'LOW',
    abuse_confidence_score INT NOT NULL DEFAULT 0,
    total_reports INT NOT NULL DEFAULT 0,
    distinct_users INT NOT NULL DEFAULT 0,
    is_vpn VARCHAR(20) NOT NULL DEFAULT 'Unknown',
    is_tor VARCHAR(20) NOT NULL DEFAULT 'Unknown',
    is_hosting VARCHAR(20) NOT NULL DEFAULT 'Unknown',
    is_attacker VARCHAR(20) NOT NULL DEFAULT 'Unknown',
    is_spam VARCHAR(20) NOT NULL DEFAULT 'Unknown',
    is_bot VARCHAR(20) NOT NULL DEFAULT 'Unknown',
    is_anonymous VARCHAR(20) NOT NULL DEFAULT 'Unknown',
    blacklist_status VARCHAR(50) NOT NULL DEFAULT 'Clean',
    country_code VARCHAR(10),
    country_name VARCHAR(100),
    region VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10, 6),
    longitude DECIMAL(10, 6),
    timezone VARCHAR(50),
    asn VARCHAR(50),
    asn_name VARCHAR(255),
    isp VARCHAR(255),
    connection_type VARCHAR(100),
    usage_type VARCHAR(100),
    domain_name VARCHAR(255),
    ip_age VARCHAR(50),
    last_seen_date VARCHAR(50),
    ml_risk_probability DECIMAL(5, 4) DEFAULT 0.0000,
    ml_predicted_label VARCHAR(50) DEFAULT 'Low Risk',
    recommendation_summary TEXT,
    raw_data_json LONGTEXT,
    is_simulated TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_risk_level (risk_level),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Security Actions & Audit Log Table (Block / Allow / Flag)
CREATE TABLE IF NOT EXISTS security_actions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    action_type ENUM('BLOCK', 'ALLOW', 'FLAG', 'UNBLOCK') NOT NULL,
    risk_score_at_action INT DEFAULT 0,
    risk_level_at_action VARCHAR(20) DEFAULT 'UNKNOWN',
    reason TEXT NOT NULL,
    operator_name VARCHAR(100) DEFAULT 'Security Analyst',
    authorization_confirmed TINYINT(1) NOT NULL DEFAULT 1,
    action_metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_action_ip (ip_address),
    INDEX idx_action_type (action_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. IP Intelligence Cache Table (for API rate-limit conservation)
CREATE TABLE IF NOT EXISTS ip_reputation_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    cached_payload LONGTEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_cache_ip (ip_address),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Connected Bank Accounts Table (Req 5, 6, 7, 10, 11, 12)
CREATE TABLE IF NOT EXISTS bank_connections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    institution_id VARCHAR(100) NOT NULL,
    institution_name VARCHAR(255) NOT NULL,
    institution_logo VARCHAR(255),
    account_id VARCHAR(100) NOT NULL,
    account_name VARCHAR(255) NOT NULL,
    account_type VARCHAR(50) NOT NULL DEFAULT 'Checking',
    masked_account_number VARCHAR(50) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    available_balance DECIMAL(12, 2) DEFAULT 0.00,
    connection_status ENUM('CONNECTED', 'DISCONNECTED') NOT NULL DEFAULT 'CONNECTED',
    is_simulated TINYINT(1) NOT NULL DEFAULT 0,
    consent_granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    consent_expires_at TIMESTAMP NULL,
    scopes_granted TEXT,
    auth_token_ref VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_conn_status (connection_status),
    INDEX idx_inst (institution_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. User-Consented Bank Transactions Table (Req 8, 9, 10)
CREATE TABLE IF NOT EXISTS bank_transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    connection_id INT NOT NULL,
    transaction_id VARCHAR(100) NOT NULL UNIQUE,
    merchant_name VARCHAR(255) NOT NULL,
    merchant_category VARCHAR(100) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    transaction_date VARCHAR(50) NOT NULL,
    transaction_type ENUM('DEBIT', 'CREDIT') NOT NULL DEFAULT 'DEBIT',
    origin_ip VARCHAR(45) NOT NULL,
    origin_location VARCHAR(255) DEFAULT 'Unknown',
    ip_risk_score INT DEFAULT 0,
    fraud_status ENUM('NORMAL', 'SUSPICIOUS', 'FLAGGED') NOT NULL DEFAULT 'NORMAL',
    fraud_reason TEXT,
    is_simulated TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_trans_conn (connection_id),
    INDEX idx_trans_fraud (fraud_status),
    INDEX idx_trans_ip (origin_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ========================================================
-- Seed Initial Demonstrative Records for Evaluation & Testing
-- ========================================================

INSERT INTO ip_analyses (
    ip_address, ip_version, risk_score, risk_level, abuse_confidence_score, 
    total_reports, distinct_users, is_vpn, is_tor, is_hosting, is_attacker, is_spam,
    is_bot, is_anonymous, blacklist_status, country_code, country_name, region, city, 
    latitude, longitude, timezone, asn, asn_name, isp, connection_type, usage_type, 
    domain_name, ip_age, last_seen_date, ml_risk_probability, ml_predicted_label, 
    recommendation_summary, is_simulated
) VALUES 
(
    '185.220.101.5', 'IPv4', 96, 'HIGH', 100, 
    842, 194, 'Yes', 'Yes', 'Yes', 'Suspected', 'Yes', 
    'Yes', 'Yes', 'Listed (5 RBLs)', 'DE', 'Germany', 'Saxony', 'Dresden', 
    51.050400, 13.737300, 'Europe/Berlin', 'AS208294', 'Zwiebelfreunde e.V.', 'Tor Exit Relay Services', 'Data Center', 'Hosting / Transit', 
    'torservers.net', '8 years', '2 minutes ago', 0.9850, 'High Risk Malicious', 
    'Critical Threat: Confirmed active Tor exit node involved in high-volume SSH brute force, credential stuffing, and vulnerability probing. Strongly recommend perimeter firewall block.', 0
),
(
    '198.51.100.84', 'IPv4', 78, 'HIGH', 75, 
    312, 68, 'Yes', 'No', 'Yes', 'Suspected', 'Yes', 
    'Suspected', 'Yes', 'Listed (2 RBLs)', 'RU', 'Russian Federation', 'Moscow', 'Moscow', 
    55.755800, 37.617300, 'Europe/Moscow', 'AS49505', 'Selectel Network', 'FastFlux Cloud VPS', 'Broadband / VPN', 'Commercial Proxy', 
    'anonymous-vpn-gate.ru', '3 years', '18 minutes ago', 0.8420, 'High Risk Proxy', 
    'High Risk: Residential proxy relay with reported port scans on TCP/3389 (RDP) and automated CMS exploit attempts. Restrict administrative endpoints.', 0
),
(
    '104.28.19.74', 'IPv4', 45, 'MEDIUM', 22, 
    18, 9, 'Yes', 'No', 'Yes', 'No', 'No', 
    'No', 'Yes', 'Clean', 'US', 'United States', 'California', 'San Francisco', 
    37.774900, -122.419400, 'America/Los_Angeles', 'AS13335', 'Cloudflare, Inc.', 'Cloudflare WARP CDN', 'Anycast Edge', 'Content Delivery Network', 
    'cloudflare.com', '12 years', '3 hours ago', 0.4210, 'Medium Risk Suspicious', 
    'Moderate Suspicion: Legitimate Cloudflare privacy relay / WARP client. Potential for rate-limit bypass. Enforce CAPTCHA challenge rather than outright block.', 0
),
(
    '8.8.8.8', 'IPv4', 5, 'LOW', 0, 
    0, 0, 'No', 'No', 'No', 'No', 'No', 
    'No', 'No', 'Clean', 'US', 'United States', 'California', 'Mountain View', 
    37.405600, -122.077500, 'America/Los_Angeles', 'AS15169', 'Google LLC', 'Google Public DNS', 'Anycast DNS', 'Infrastructure', 
    'dns.google', '25 years', 'Active Now', 0.0210, 'Low Risk Clean', 
    'Safe Infrastructure: Verified Google Public DNS recursive resolver. Legitimate global DNS resolution traffic. Whitelist for DNS queries.', 0
),
(
    '1.1.1.1', 'IPv4', 4, 'LOW', 0, 
    0, 0, 'No', 'No', 'No', 'No', 'No', 
    'No', 'No', 'Clean', 'AU', 'Australia', 'Queensland', 'South Brisbane', 
    -27.476600, 153.016600, 'Australia/Brisbane', 'AS13335', 'Cloudflare, Inc.', 'APNIC and Cloudflare DNS', 'Anycast DNS', 'Infrastructure', 
    'one.one.one.one', '20 years', 'Active Now', 0.0150, 'Low Risk Clean', 
    'Safe Infrastructure: Verified Cloudflare / APNIC 1.1.1.1 DNS resolver. Whitelisted as authoritative recursive nameserver.', 0
);

-- Seed Initial Security Action Logs
INSERT INTO security_actions (ip_address, action_type, risk_score_at_action, risk_level_at_action, reason, operator_name, authorization_confirmed)
VALUES 
('185.220.101.5', 'BLOCK', 96, 'HIGH', 'Aggressive brute-force on port 22 and Tor exit relay policy violation.', 'Admin Analyst (SecOps)', 1),
('8.8.8.8', 'ALLOW', 5, 'LOW', 'Trusted Google Anycast Public DNS resolver.', 'Security Lead', 1);
