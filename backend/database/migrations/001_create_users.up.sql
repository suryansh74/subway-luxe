-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL,
    email VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    phone_country_code VARCHAR(5),
    image_path VARCHAR(255),
    role VARCHAR(20) NOT NULL DEFAULT 'customer',
    address TEXT,
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
    email_otp VARCHAR(6),
    email_otp_expires_at TIMESTAMP,
    email_otp_attempts INT NOT NULL DEFAULT 0,
    phone_otp VARCHAR(6),
    phone_otp_expires_at TIMESTAMP,
    phone_otp_attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);