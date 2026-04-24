-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 LIMIT 1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 LIMIT 1;

-- name: GetUserByPhone :one
SELECT * FROM users WHERE phone = $1 LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (name, email, password, role)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: UpdateUser :one
UPDATE users 
SET name = $2, email = $3, phone = $4, phone_country_code = $5, image_path = $6, role = $7, address = $8, is_email_verified = $9, is_phone_verified = $10, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdatePassword :one
UPDATE users 
SET password = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: SetEmailOTP :one
UPDATE users 
SET email_otp = $2, email_otp_expires_at = $3, email_otp_attempts = $4, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: SetPhoneOTP :one
UPDATE users 
SET phone_otp = $2, phone_otp_expires_at = $3, phone_otp_attempts = $4, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: ClearEmailOTP :one
UPDATE users 
SET email_otp = NULL, email_otp_expires_at = NULL, email_otp_attempts = 0, is_email_verified = true, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: ClearPhoneOTP :one
UPDATE users 
SET phone_otp = NULL, phone_otp_expires_at = NULL, phone_otp_attempts = 0, is_phone_verified = true, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateUserRole :one
UPDATE users 
SET role = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;