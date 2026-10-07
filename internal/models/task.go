package models

import "time"

type Task struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	DueDate     time.Time `json:"due_date"`
	Visibility  string    `json:"visibility"`
	Status      string    `json:"status"`
	CreatedBy   int       `json:"created_by"`
	AuthorName  string    `json:"author_name"`
	CreatedAt   time.Time `json:"created_at"`
}
