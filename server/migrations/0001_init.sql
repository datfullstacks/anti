CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Plans
CREATE TYPE plan_tier AS ENUM ('starter', 'team', 'pro', 'enterprise');

CREATE TABLE plans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tier plan_tier NOT NULL UNIQUE,
    name TEXT NOT NULL,
    max_profiles INT NOT NULL,
    max_seats INT NOT NULL,
    max_concurrent_sessions INT NOT NULL,
    storage_gb INT NOT NULL,
    price_monthly_cents INT NOT NULL,
    stripe_price_id TEXT
);

INSERT INTO plans (tier, name, max_profiles, max_seats, max_concurrent_sessions, storage_gb, price_monthly_cents) VALUES
    ('starter',    'Starter',    10,   1,  2,   5,   900),
    ('team',       'Team',       100,  5,  10,  20,  2900),
    ('pro',        'Pro',        500,  20, 50,  100, 7900),
    ('enterprise', 'Enterprise', -1,   -1, -1,  -1,  0);

-- Orgs (tenant isolation)
CREATE TABLE orgs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    plan_id UUID NOT NULL REFERENCES plans(id),
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    subscription_status TEXT NOT NULL DEFAULT 'trialing',
    trial_ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users
CREATE TYPE user_role AS ENUM ('owner', 'admin', 'member');

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role user_role NOT NULL DEFAULT 'member',
    is_active BOOL NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_org ON users(org_id);
CREATE INDEX idx_users_email ON users(email);

-- API keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_org ON api_keys(org_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- Proxies
CREATE TYPE proxy_protocol AS ENUM ('http', 'https', 'socks5');

CREATE TABLE proxies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    protocol proxy_protocol NOT NULL DEFAULT 'socks5',
    host TEXT NOT NULL,
    port INT NOT NULL,
    username TEXT,
    password TEXT,
    country_code CHAR(2),
    is_active BOOL NOT NULL DEFAULT TRUE,
    last_checked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_proxies_org ON proxies(org_id);

-- Fingerprint templates
CREATE TABLE fingerprints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Browser
    user_agent TEXT NOT NULL,
    platform TEXT NOT NULL,
    hardware_concurrency INT NOT NULL,
    device_memory INT NOT NULL,
    -- Screen
    screen_width INT NOT NULL,
    screen_height INT NOT NULL,
    color_depth INT NOT NULL DEFAULT 24,
    pixel_ratio FLOAT NOT NULL DEFAULT 1.0,
    -- Locale
    timezone TEXT NOT NULL,
    language TEXT NOT NULL,
    languages TEXT[] NOT NULL,
    -- Canvas noise (seed fed to C++ patch)
    canvas_noise_seed BIGINT NOT NULL,
    audio_noise_seed BIGINT NOT NULL,
    -- WebGL
    webgl_vendor TEXT NOT NULL,
    webgl_renderer TEXT NOT NULL,
    -- Fonts
    font_noise_seed BIGINT NOT NULL,
    -- Network fingerprint
    tcp_ttl INT NOT NULL DEFAULT 64,
    tcp_window_size INT NOT NULL DEFAULT 65535,
    ja3_profile TEXT NOT NULL DEFAULT 'chrome_120',
    http2_profile TEXT NOT NULL DEFAULT 'chrome_120',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fingerprints_org ON fingerprints(org_id);

-- Profiles
CREATE TABLE profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    fingerprint_id UUID NOT NULL REFERENCES fingerprints(id),
    proxy_id UUID REFERENCES proxies(id),
    notes TEXT,
    tags TEXT[] NOT NULL DEFAULT '{}',
    -- Session state (encrypted)
    cookies_enc BYTEA,
    local_storage_enc BYTEA,
    -- Binary version this profile was last used with
    last_binary_version TEXT,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_profiles_org ON profiles(org_id);
CREATE INDEX idx_profiles_created_by ON profiles(created_by);

-- Sessions
CREATE TYPE session_status AS ENUM ('launching', 'running', 'closed', 'crashed');

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    status session_status NOT NULL DEFAULT 'launching',
    client_hostname TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    duration_secs INT GENERATED ALWAYS AS (
        CASE WHEN ended_at IS NOT NULL
            THEN EXTRACT(EPOCH FROM ended_at - started_at)::INT
            ELSE NULL END
    ) STORED
);

CREATE INDEX idx_sessions_org ON sessions(org_id);
CREATE INDEX idx_sessions_profile ON sessions(profile_id);
CREATE INDEX idx_sessions_status ON sessions(status);

-- Binary versions (for auto-updater)
CREATE TABLE binary_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    version TEXT NOT NULL UNIQUE,
    linux_url TEXT,
    linux_sha256 TEXT,
    windows_url TEXT,
    windows_sha256 TEXT,
    is_latest BOOL NOT NULL DEFAULT FALSE,
    release_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    user_id UUID,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id UUID,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_org ON audit_log(org_id, created_at DESC);
