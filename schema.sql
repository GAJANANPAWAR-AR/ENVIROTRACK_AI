-- ===========================================================
--  USERS TABLE
-- ===========================================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(150) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- ===========================================================
--  WASTE REPORTS TABLE
-- ===========================================================

CREATE TABLE IF NOT EXISTS waste_reports (
    id SERIAL PRIMARY KEY,

    latitude DOUBLE PRECISION NOT NULL,
    longitude DOUBLE PRECISION NOT NULL,

    description TEXT,
    image_url TEXT NOT NULL,
    reported_by VARCHAR(255),

    reported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    is_cleaned BOOLEAN DEFAULT FALSE,
    cleaned_by_user_id INTEGER REFERENCES users(id),
    cleaned_image_url TEXT,
    cleaned_at TIMESTAMP WITH TIME ZONE,

    cleanup_verified BOOLEAN DEFAULT FALSE,
    verification_confidence VARCHAR(20),
    ai_comparison_result TEXT,

    points INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_reports_is_cleaned ON waste_reports(is_cleaned);
CREATE INDEX IF NOT EXISTS idx_reports_reported_by ON waste_reports(reported_by);
