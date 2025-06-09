package orm

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/neatflowcv/identity/internal/pkg/domain"
	"github.com/neatflowcv/identity/internal/pkg/repository/core"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var _ core.Repository = (*Repository)(nil)

type UserModel struct {
	Username string `gorm:"primaryKey;column:username"`
	Password string `gorm:"column:password;not null"`
}

func (UserModel) TableName() string {
	return "users"
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

	var user UserModel

	err = db.AutoMigrate(&user)
	if err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &Repository{db: db}, nil
}

func (r *Repository) CreateUser(ctx context.Context, user *domain.User) (*domain.User, error) {
	model := &UserModel{
		Username: user.Username(),
		Password: user.Password(),
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

	err := r.db.WithContext(ctx).First(&model, UserModel{Username: username}).Error //nolint:exhaustruct
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, core.ErrUserNotFound
		}

		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	user := domain.NewUser(model.Username, model.Password)

	return user, nil
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
