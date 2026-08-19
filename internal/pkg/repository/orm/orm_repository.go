package orm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/repository/core"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var _ core.Repository = (*Repository)(nil)

type UserModel struct {
	Username     string `gorm:"primaryKey;column:username"`
	PasswordHash string `gorm:"column:password_hash"`
}

func (UserModel) TableName() string {
	return "users"
}

type RefreshSessionModel struct {
	FamilyID  string     `gorm:"primaryKey;column:family_id"`
	Username  string     `gorm:"column:username;index"`
	TokenID   string     `gorm:"column:token_id"`
	TokenHash string     `gorm:"column:token_hash"`
	ExpiresAt time.Time  `gorm:"column:expires_at"`
	RevokedAt *time.Time `gorm:"column:revoked_at"`
}

func (RefreshSessionModel) TableName() string {
	return "refresh_sessions"
}

type Repository struct {
	db *gorm.DB
}

func NewRepository(dsn string) (*Repository, error) {
	var config gorm.Config

	db, err := gorm.Open(postgres.Open(dsn), &config)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	err = db.AutoMigrate(new(UserModel), new(RefreshSessionModel))
	if err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &Repository{db: db}, nil
}

func (r *Repository) CreateUser(ctx context.Context, user *domain.User) (*domain.User, error) {
	model := &UserModel{
		Username:     user.Username(),
		PasswordHash: user.PasswordHash(),
	}

	err := r.db.WithContext(ctx).Create(model).Error
	if err != nil {
		// GORM에서 중복 키 에러 확인
		if r.isDuplicateKeyError(err) {
			return nil, core.ErrUserExists
		}

		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}
func (r *Repository) GetUser(ctx context.Context, username string) (*domain.User, error) {
	var model UserModel

	err := r.db.WithContext(ctx).
		Select("username", "password_hash").
		First(&model, UserModel{Username: username}).Error //nolint:exhaustruct
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, core.ErrUserNotFound
		}

		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	user := domain.NewUserWithPasswordHash(model.Username, model.PasswordHash)

	return user, nil
}

func (r *Repository) CreateRefreshSession(ctx context.Context, session *domain.RefreshSession) error {
	model := &RefreshSessionModel{
		FamilyID:  session.FamilyID,
		Username:  string(session.Username),
		TokenID:   session.TokenID,
		TokenHash: session.TokenHash,
		ExpiresAt: session.ExpiresAt,
		RevokedAt: session.RevokedAt,
	}

	err := r.db.WithContext(ctx).Create(model).Error
	if err != nil {
		if r.isDuplicateKeyError(err) {
			return core.ErrRefreshSessionExists
		}

		return fmt.Errorf("failed to create refresh session: %w", err)
	}

	return nil
}

func (r *Repository) RotateRefreshToken(ctx context.Context, rotation *domain.RefreshTokenRotation) error {
	invalid := false

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(new(RefreshSessionModel)).
			Where(
				"family_id = ? AND token_id = ? AND token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
				rotation.FamilyID,
				rotation.CurrentTokenID,
				rotation.CurrentHash,
				rotation.Now,
			).
			Updates(map[string]any{
				"token_id":   rotation.NextTokenID,
				"token_hash": rotation.NextHash,
				"expires_at": rotation.ExpiresAt,
			})
		if result.Error != nil {
			return fmt.Errorf("failed to rotate refresh token: %w", result.Error)
		}

		if result.RowsAffected == 1 {
			return nil
		}

		invalid = true

		return tx.Model(new(RefreshSessionModel)).
			Where("family_id = ? AND revoked_at IS NULL", rotation.FamilyID).
			Update("revoked_at", rotation.Now).Error
	})
	if err != nil {
		return fmt.Errorf("failed to rotate refresh token transaction: %w", err)
	}

	if invalid {
		return core.ErrRefreshTokenInvalid
	}

	return nil
}

func (r *Repository) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	now := time.Now()

	err := r.db.WithContext(ctx).
		Model(new(RefreshSessionModel)).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		Update("revoked_at", now).Error
	if err != nil {
		return fmt.Errorf("failed to revoke refresh family: %w", err)
	}

	return nil
}

// isDuplicateKeyError 데이터베이스 중복 키 에러인지 확인
func (r *Repository) isDuplicateKeyError(err error) bool {
	errStr := err.Error()
	// PostgreSQL, MySQL, SQLite 등의 중복 키 에러 메시지 패턴 확인
	return strings.Contains(errStr, "duplicate key value") || // PostgreSQL
		strings.Contains(errStr, "violates unique constraint") || // PostgreSQL
		strings.Contains(errStr, "UNIQUE constraint failed") || // SQLite
		strings.Contains(errStr, "Duplicate entry") || // MySQL
		strings.Contains(errStr, "UNIQUE KEY constraint") // SQL Server
}
