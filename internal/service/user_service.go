package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"company-portal/internal/models"
)

// User is a minimal domain object required by orchestration logic.
type User struct {
	ID           int
	Email        string
	PasswordHash string
	FullName     string
	Role         string
}

type UserRepository interface {
	Create(ctx context.Context, user *User) error
	Delete(ctx context.Context, targetID int, requesterID int) error
	GetAll(ctx context.Context) ([]*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
}

// FolderManager encapsulates external folder/account provisioning.
type FolderManager interface {
	CreateUser(ctx context.Context, login, password string) error
}

// UserService orchestrates DB writes and external API side effects.
type UserService struct {
	repo          UserRepository
	folderManager FolderManager
}

// NewUserService creates a business service with injected dependencies.
func NewUserService(repo UserRepository, folderManager FolderManager) *UserService {
	return &UserService{
		repo:          repo,
		folderManager: folderManager,
	}
}

// AddUser creates a user in DB and provisions user resources in Nextcloud.
// If external provisioning fails, a compensating DB rollback is attempted.
func (s *UserService) AddUser(ctx context.Context, user *User, cloudPassword string) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return fmt.Errorf("failed to save user to db: %w", err)
	}

	if err := s.folderManager.CreateUser(ctx, user.Email, cloudPassword); err != nil {
		rollbackErr := s.repo.Delete(ctx, user.ID, 1)
		if rollbackErr != nil {
			log.Printf("CRITICAL: failed to rollback user %d creation: %v", user.ID, rollbackErr)
			return fmt.Errorf("failed to create user in nextcloud and failed to rollback db: %w", errors.Join(err, rollbackErr))
		}

		return fmt.Errorf("failed to create user in nextcloud, db changes rolled back: %w", err)
	}

	return nil
}

func (s *UserService) GetUsers(ctx context.Context) ([]*models.User, error) {
	return s.repo.GetAll(ctx)
}

func (s *UserService) DeleteUser(ctx context.Context, targetID int, requesterID int) error {
	return s.repo.Delete(ctx, targetID, requesterID)
}

func (s *UserService) Authenticate(ctx context.Context, email, password string) (*models.User, error) {
	user, err := s.repo.GetByEmail(ctx, strings.TrimSpace(email))
	if err != nil {
		return nil, fmt.Errorf("authenticate user: %w", err)
	}
	if !user.IsActive {
		return nil, fmt.Errorf("user is inactive")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("authenticate user: %w", err)
	}

	return user, nil
}
