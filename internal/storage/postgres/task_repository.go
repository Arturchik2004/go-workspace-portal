package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"company-portal/internal/models"
)

type TaskRepository struct {
	pool *pgxpool.Pool
}

func NewTaskRepository(pool *pgxpool.Pool) *TaskRepository {
	return &TaskRepository{pool: pool}
}

func (r *TaskRepository) Create(ctx context.Context, task *models.Task) error {
	const query = `
		INSERT INTO tasks (title, description, due_date, visibility, status, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at
	`

	if err := r.pool.QueryRow(ctx, query, task.Title, task.Description, task.DueDate, task.Visibility, task.Status, task.CreatedBy).Scan(&task.ID, &task.CreatedAt); err != nil {
		return fmt.Errorf("insert task: %w", err)
	}

	return nil
}

func (r *TaskRepository) GetVisible(ctx context.Context, userID int) ([]*models.Task, error) {
	const query = `
		SELECT t.id, t.title, t.description, t.due_date, t.visibility, t.status,
		       t.created_by, u.full_name, t.created_at
		FROM tasks t
		JOIN users u ON u.id = t.created_by
		WHERE t.visibility = 'public' OR t.created_by = $1
		ORDER BY t.due_date ASC, t.created_at DESC
	`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query visible tasks: %w", err)
	}
	defer rows.Close()

	tasks := make([]*models.Task, 0)
	for rows.Next() {
		task := &models.Task{}
		if err := rows.Scan(&task.ID, &task.Title, &task.Description, &task.DueDate, &task.Visibility, &task.Status, &task.CreatedBy, &task.AuthorName, &task.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan task: %w", err)
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read tasks: %w", err)
	}

	return tasks, nil
}

func (r *TaskRepository) UpdateStatus(ctx context.Context, id int, status string) error {
	result, err := r.pool.Exec(ctx, "UPDATE tasks SET status = $1 WHERE id = $2", status, id)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("task not found")
	}
	return nil
}

func (r *TaskRepository) Delete(ctx context.Context, id int) error {
	result, err := r.pool.Exec(ctx, "DELETE FROM tasks WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete task: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("task not found")
	}
	return nil
}
