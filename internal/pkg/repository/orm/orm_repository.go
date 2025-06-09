package orm

import (
	"context"
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
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return user, nil
}

func (r *Repository) GetUser(ctx context.Context, username string) (*domain.User, error) {
	var model UserModel

	err := r.db.WithContext(ctx).First(&model, UserModel{Username: username}).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, core.ErrUserNotFound
		}
		return nil, err
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
