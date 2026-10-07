package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"company-portal/internal/models"
	"company-portal/internal/service"
)

// UserRepository persists users in PostgreSQL.
type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, user *service.User) error {
	if user == nil {
		return errors.New("user is nil")
	}

	role := user.Role
	if role == "" {
		role = "employee"
	}

	const query = `
		INSERT INTO users (email, password_hash, full_name, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`

	err := r.pool.QueryRow(ctx, query, user.Email, user.PasswordHash, user.FullName, role).Scan(&user.ID)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	user.Role = role
	return nil
}

func (r *UserRepository) Delete(ctx context.Context, targetID int, requesterID int) error {
	if targetID == 1 {
		return fmt.Errorf("cannot delete root administrator")
	}

	const query = `
		DELETE FROM users
		WHERE id = $1
		  AND (role != 'admin' OR $2 = 1)
	`

	result, err := r.pool.Exec(ctx, query, targetID, requesterID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user with id %d not found or deletion is not allowed", targetID)
	}

	return nil
}

func (r *UserRepository) GetAll(ctx context.Context) ([]*models.User, error) {
	const query = `SELECT id, email, full_name, role, is_active, created_at FROM users WHERE is_active = TRUE ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Email, &u.FullName, &u.Role, &u.IsActive, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, &u)
	}
	return users, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	const query = `
		SELECT id, email, password_hash, full_name, role, is_active, created_at
		FROM users
		WHERE email = $1
	`

	var user models.User
	if err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.Role,
		&user.IsActive,
		&user.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	return &user, nil
}
