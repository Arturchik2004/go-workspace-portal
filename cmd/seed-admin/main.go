package main

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	"company-portal/internal/storage/postgres"
)

func main() {
	_ = godotenv.Load()

	email := os.Getenv("ADMIN_EMAIL")
	if email == "" {
		email = "admin@example.com"
	}
	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		fmt.Fprintln(os.Stderr, "ADMIN_PASSWORD должен быть задан только через окружение")
		os.Exit(1)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка хэширования пароля: %v\n", err)
		os.Exit(1)
	}

	dsn := (&url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD")),
		Host:   fmt.Sprintf("%s:%s", os.Getenv("DB_HOST"), os.Getenv("DB_PORT")),
		Path:   os.Getenv("DB_NAME"),
	}).String() + "?sslmode=disable"

	pool, err := postgres.NewPool(context.Background(), dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка подключения к БД: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	const query = `
		INSERT INTO users (email, password_hash, full_name, role)
		VALUES ($1, $2, $3, 'admin')
		ON CONFLICT (email) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			full_name = EXCLUDED.full_name,
			role = 'admin'
	`

	if _, err := pool.Exec(context.Background(), query, email, string(passwordHash), "Администратор"); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка создания администратора: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Администратор %s создан или обновлён. Пароль не выводится.\n", email)
}
