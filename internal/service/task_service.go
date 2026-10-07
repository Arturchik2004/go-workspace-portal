package service

import (
	"context"
	"company-portal/internal/models"
)

type TaskRepository interface {
	Create(ctx context.Context, task *models.Task) error
	GetVisible(ctx context.Context, userID int) ([]*models.Task, error)
	UpdateStatus(ctx context.Context, id int, status string) error
	Delete(ctx context.Context, id int) error
}

type TaskService struct {
	repo TaskRepository
}

func NewTaskService(repo TaskRepository) *TaskService {
	return &TaskService{repo: repo}
}

func (s *TaskService) Create(ctx context.Context, task *models.Task) error {
	return s.repo.Create(ctx, task)
}

func (s *TaskService) GetVisible(ctx context.Context, userID int) ([]*models.Task, error) {
	return s.repo.GetVisible(ctx, userID)
}

func (s *TaskService) UpdateStatus(ctx context.Context, taskID int, status string) error {
	return s.repo.UpdateStatus(ctx, taskID, status)
}

func (s *TaskService) DeleteTask(ctx context.Context, taskID int) error {
	return s.repo.Delete(ctx, taskID)
}
