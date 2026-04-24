package repositories

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/suryansh74/subway-luxe/database/sqlc"
	"github.com/suryansh74/subway-luxe/internal/auth/domain"
)

type AuthRepository struct {
	q *sqlc.Queries
}

func NewAuthRepository(pool *pgxpool.Pool) *AuthRepository {
	return &AuthRepository{
		q: sqlc.New(pool),
	}
}

func (r *AuthRepository) Create(ctx context.Context, arg domain.CreateUserParams) (*domain.User, error) {
	user, err := r.q.CreateUser(ctx, sqlc.CreateUserParams{
		Name:     arg.Name,
		Email:    arg.Email,
		Password: arg.Password,
		Role:     arg.Role,
	})
	if err != nil {
		return nil, err
	}
	return mapToDomainUser(user), nil
}

func (r *AuthRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	user, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return mapToDomainUser(user), nil
}

func (r *AuthRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	var uid pgtype.UUID
	if err := uid.Scan(id); err != nil {
		return nil, err
	}
	user, err := r.q.GetUserByID(ctx, uid)
	if err != nil {
		return nil, err
	}
	return mapToDomainUser(user), nil
}

func (r *AuthRepository) GetByPhone(ctx context.Context, phone string) (*domain.User, error) {
	user, err := r.q.GetUserByPhone(ctx, pgtype.Text{String: phone, Valid: true})
	if err != nil {
		return nil, err
	}
	return mapToDomainUser(user), nil
}

func (r *AuthRepository) Update(ctx context.Context, arg domain.UpdateUserParams) (*domain.User, error) {
	var uid pgtype.UUID
	if err := uid.Scan(arg.ID); err != nil {
		return nil, err
	}
	user, err := r.q.UpdateUser(ctx, sqlc.UpdateUserParams{
		ID:               uid,
		Name:             arg.Name,
		Email:            arg.Email,
		Phone:            mapPtrToText(arg.Phone),
		PhoneCountryCode: mapPtrToText(arg.PhoneCountryCode),
		ImagePath:        mapPtrToText(arg.ImagePath),
		Role:             arg.Role,
		Address:          mapPtrToText(arg.Address),
		IsEmailVerified:  arg.IsEmailVerified,
		IsPhoneVerified:  arg.IsPhoneVerified,
	})
	if err != nil {
		return nil, err
	}
	return mapToDomainUser(user), nil
}

func (r *AuthRepository) SetEmailOTP(ctx context.Context, userID string, otp string, expiresAt string, attempts int) (*domain.User, error) {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return nil, err
	}
	expiresTime, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, err
	}
	user, err := r.q.SetEmailOTP(ctx, sqlc.SetEmailOTPParams{
		ID:                uid,
		EmailOtp:          pgtype.Text{String: otp, Valid: true},
		EmailOtpExpiresAt: pgtypeTimestamp(expiresTime),
		EmailOtpAttempts:  int32(attempts),
	})
	if err != nil {
		return nil, err
	}
	return mapToDomainUser(user), nil
}

func (r *AuthRepository) SetPhoneOTP(ctx context.Context, userID string, otp string, expiresAt string, attempts int) (*domain.User, error) {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return nil, err
	}
	expiresTime, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, err
	}
	user, err := r.q.SetPhoneOTP(ctx, sqlc.SetPhoneOTPParams{
		ID:                uid,
		PhoneOtp:          pgtype.Text{String: otp, Valid: true},
		PhoneOtpExpiresAt: pgtypeTimestamp(expiresTime),
		PhoneOtpAttempts:  int32(attempts),
	})
	if err != nil {
		return nil, err
	}
	return mapToDomainUser(user), nil
}

func (r *AuthRepository) ClearEmailOTP(ctx context.Context, userID string) (*domain.User, error) {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return nil, err
	}
	user, err := r.q.ClearEmailOTP(ctx, uid)
	if err != nil {
		return nil, err
	}
	return mapToDomainUser(user), nil
}

func (r *AuthRepository) ClearPhoneOTP(ctx context.Context, userID string) (*domain.User, error) {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return nil, err
	}
	user, err := r.q.ClearPhoneOTP(ctx, uid)
	if err != nil {
		return nil, err
	}
	return mapToDomainUser(user), nil
}

func (r *AuthRepository) UpdateRole(ctx context.Context, userID string, role string) (*domain.User, error) {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return nil, err
	}
	user, err := r.q.UpdateUserRole(ctx, sqlc.UpdateUserRoleParams{
		ID:   uid,
		Role: role,
	})
	if err != nil {
		return nil, err
	}
	return mapToDomainUser(user), nil
}

func mapToDomainUser(user sqlc.User) *domain.User {
	d := &domain.User{
		ID:               uuidFromPgtype(user.ID),
		Name:             user.Name,
		Email:            user.Email,
		Password:         user.Password,
		Role:             domain.Role(user.Role),
		IsEmailVerified:  user.IsEmailVerified,
		IsPhoneVerified:  user.IsPhoneVerified,
		EmailOtpAttempts: int(user.EmailOtpAttempts),
		PhoneOtpAttempts: int(user.PhoneOtpAttempts),
		CreatedAt:        user.CreatedAt.Time,
		UpdatedAt:        user.UpdatedAt.Time,
	}
	if user.Phone.Valid {
		d.Phone = &user.Phone.String
	}
	if user.PhoneCountryCode.Valid {
		d.PhoneCountryCode = &user.PhoneCountryCode.String
	}
	if user.ImagePath.Valid {
		d.ImagePath = &user.ImagePath.String
	}
	if user.Address.Valid {
		d.Address = &user.Address.String
	}
	if user.EmailOtp.Valid {
		d.EmailOtp = &user.EmailOtp.String
	}
	if user.EmailOtpExpiresAt.Valid {
		d.EmailOtpExpiresAt = &user.EmailOtpExpiresAt.Time
	}
	if user.PhoneOtp.Valid {
		d.PhoneOtp = &user.PhoneOtp.String
	}
	if user.PhoneOtpExpiresAt.Valid {
		d.PhoneOtpExpiresAt = &user.PhoneOtpExpiresAt.Time
	}
	return d
}

func uuidFromPgtype(u pgtype.UUID) [16]byte {
	return u.Bytes
}

func mapPtrToText(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: *s, Valid: true}
}

func pgtypeTimestamp(t time.Time) pgtype.Timestamp {
	return pgtype.Timestamp{Time: t, Valid: true}
}
