package auth

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User (domain)

type User struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	Email        string         `gorm:"not null;unique" json:"email"`
	PasswordHash string         `gorm:"not null" json:"-"`
	FirstName    string         `gorm:"not null" json:"first_name"`
	LastName     string         `gorm:"not null" json:"last_name"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"deleted_at"`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}
