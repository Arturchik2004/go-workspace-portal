package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/joho/godotenv"

	"company-portal/internal/clients/nextcloud"
	"company-portal/internal/models"
	"company-portal/internal/service"
	"company-portal/internal/storage/postgres"
)

type DashboardData struct {
	FullName string
	Email    string
	Role     string
	CloudURL string
	UserID   int
}

type localFolderManager struct{}

type activeUser struct {
	ID       int       `json:"id"`
	Email    string    `json:"email"`
	FullName string    `json:"full_name"`
	Role     string    `json:"role"`
	LastSeen time.Time `json:"last_seen"`
}

type activeUserRegistry struct {
	mu      sync.Mutex
	users   map[int]activeUser
	timeout time.Duration
}

func newActiveUserRegistry(timeout time.Duration) *activeUserRegistry {
	return &activeUserRegistry{users: make(map[int]activeUser), timeout: timeout}
}

func (r *activeUserRegistry) touch(user *DashboardData) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user.UserID] = activeUser{ID: user.UserID, Email: user.Email, FullName: user.FullName, Role: user.Role, LastSeen: time.Now()}
}

func (r *activeUserRegistry) list() []activeUser {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	users := make([]activeUser, 0, len(r.users))
	for id, user := range r.users {
		if now.Sub(user.LastSeen) > r.timeout {
			delete(r.users, id)
			continue
		}
		users = append(users, user)
	}
	return users
}

func (localFolderManager) CreateUser(context.Context, string, string) error {
	return nil
}

func firstExistingPath(candidates ...string) (string, error) {
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("ни один из путей не найден: %s", strings.Join(candidates, ", "))
}

func isAddressInUse(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			if errno, ok := sysErr.Err.(syscall.Errno); ok {
				return errno == syscall.EADDRINUSE
			}
		}
	}

	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "address already in use") ||
		strings.Contains(errText, "only one usage of each socket address")
}

func buildPostgresDSNFromEnv() (string, error) {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	name := os.Getenv("DB_NAME")

	if host == "" || port == "" || user == "" || password == "" || name == "" {
		return "", fmt.Errorf("database environment is incomplete: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME are required")
	}

	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, name), nil
}

func loadDotEnvIfPresent(wd string) {
	envPath, err := firstExistingPath(
		"./.env",
		"../../.env",
		filepath.Join(wd, ".env"),
	)
	if err != nil {
		log.Printf(".env не найден, использую переменные окружения процесса")
		return
	}

	if err := godotenv.Load(envPath); err != nil {
		log.Printf("Не удалось загрузить .env (%s): %v", envPath, err)
	}
}

func parseAuthToken(r *http.Request, jwtSecret []byte) (*DashboardData, error) {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid auth token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid auth claims")
	}

	fullName, ok := claims["full_name"].(string)
	if !ok || fullName == "" {
		return nil, fmt.Errorf("missing user name claim")
	}
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return nil, fmt.Errorf("missing user email claim")
	}

	role, ok := claims["role"].(string)
	if !ok || role == "" {
		return nil, fmt.Errorf("missing user role claim")
	}
	userIDValue, ok := claims["user_id"].(float64)
	if !ok || userIDValue < 1 {
		return nil, fmt.Errorf("missing user id claim")
	}

	return &DashboardData{FullName: fullName, Email: email, Role: role, UserID: int(userIDValue)}, nil
}

func protectedPage(tmpl *template.Template, jwtSecret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}

		data, err := parseAuthToken(r, jwtSecret)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		data.CloudURL = os.Getenv("NEXTCLOUD_URL")

		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Ошибка рендера страницы: %v", err)
			http.Error(w, "Ошибка рендера страницы", http.StatusInternalServerError)
		}
	}
}

func envBool(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return value == "1" || value == "true" || value == "yes"
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self' localhost; frame-src 'self' localhost; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;")
		next.ServeHTTP(w, r)
	})
}

func main() {

	ctx := context.Background()

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Ошибка определения рабочей директории: %v", err)
	}

	loadDotEnvIfPresent(wd)

	jwtSecretValue := os.Getenv("JWT_SECRET")
	if len(jwtSecretValue) < 32 {
		log.Fatal("JWT_SECRET должен быть задан и содержать минимум 32 символа")
	}
	jwtSecret := []byte(jwtSecretValue)

	dsn, err := buildPostgresDSNFromEnv()
	if err != nil {
		log.Fatalf("Ошибка конфигурации БД: %v", err)
	}

	pool, err := postgres.NewPool(ctx, dsn)
	if err != nil {
		log.Fatalf("Ошибка подключения к БД: %v", err)
	}
	defer pool.Close()

	migrationsDir, err := firstExistingPath(
		"./migrations",
		"../../migrations",
		filepath.Join(wd, "migrations"),
	)
	if err != nil {
		log.Fatalf("Не удалось найти папку с миграциями: %v", err)
	}

	if err := postgres.RunMigrations(ctx, pool, migrationsDir); err != nil {
		log.Fatalf("Ошибка при инициализации базы данных: %v", err)
	}

	userRepo := postgres.NewUserRepository(pool)
	var folderManager service.FolderManager = localFolderManager{}
	if envBool("NEXTCLOUD_ENABLED") {
		folderManager = nextcloud.NewClient(
			os.Getenv("NEXTCLOUD_URL"),
			os.Getenv("NEXTCLOUD_USER"),
			os.Getenv("NEXTCLOUD_APP_PASSWORD"),
		)
	}
	userService := service.NewUserService(userRepo, folderManager)
	taskService := service.NewTaskService(postgres.NewTaskRepository(pool))
	activeUsers := newActiveUserRegistry(5 * time.Minute)

	templatePath, err := firstExistingPath(
		"./web/templates/dashboard.html",
		"../../web/templates/dashboard.html",
		filepath.Join(wd, "web", "templates", "dashboard.html"),
	)
	if err != nil {
		log.Fatalf("Ошибка поиска шаблона: %v", err)
	}

	staticDir, err := firstExistingPath(
		"./web/static",
		"../../web/static",
		filepath.Join(wd, "web", "static"),
	)
	if err != nil {
		log.Fatalf("Ошибка поиска статических файлов: %v", err)
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Fatalf("Ошибка загрузки шаблона: %v", err)
	}

	loginTemplatePath, err := firstExistingPath(
		"./web/templates/login.html",
		"../../web/templates/login.html",
		filepath.Join(wd, "web", "templates", "login.html"),
	)
	if err != nil {
		log.Fatalf("Ошибка поиска шаблона входа: %v", err)
	}

	loginTmpl, err := template.ParseFiles(loginTemplatePath)
	if err != nil {
		log.Fatalf("Ошибка загрузки шаблона входа: %v", err)
	}

	pageTemplates := make(map[string]*template.Template)
	for _, page := range []string{"tasks", "reports", "calendar", "profile", "employees"} {
		pagePath, err := firstExistingPath(
			"./web/templates/"+page+".html",
			"../../web/templates/"+page+".html",
			filepath.Join(wd, "web", "templates", page+".html"),
		)
		if err != nil {
			log.Fatalf("Ошибка поиска шаблона %s: %v", page, err)
		}
		pageTemplates[page], err = template.ParseFiles(pagePath)
		if err != nil {
			log.Fatalf("Ошибка загрузки шаблона %s: %v", page, err)
		}
	}

	mux := http.NewServeMux()

	fileServer := http.FileServer(http.Dir(staticDir))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}

		if err := loginTmpl.Execute(w, nil); err != nil {
			log.Printf("Ошибка рендера страницы входа: %v", err)
		}
	})

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "Некорректный запрос", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Email) == "" || req.Password == "" {
			http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
			return
		}

		user, err := userService.Authenticate(r.Context(), req.Email, req.Password)
		if err != nil {
			http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id":   user.ID,
			"email":     user.Email,
			"full_name": user.FullName,
			"role":      user.Role,
			"exp":       time.Now().Add(24 * time.Hour).Unix(),
		})
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			log.Printf("Ошибка подписи JWT: %v", err)
			http.Error(w, "Внутренняя ошибка", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    tokenString,
			Path:     "/",
			MaxAge:   24 * 60 * 60,
			HttpOnly: true,
			Secure:   envBool("COOKIE_SECURE"),
			SameSite: http.SameSiteLaxMode,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})

	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: envBool("COOKIE_SECURE"), SameSite: http.SameSiteLaxMode})
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   envBool("COOKIE_SECURE"),
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	mux.HandleFunc("/tasks", protectedPage(pageTemplates["tasks"], jwtSecret))
	mux.HandleFunc("/reports", protectedPage(pageTemplates["reports"], jwtSecret))
	mux.HandleFunc("/calendar", protectedPage(pageTemplates["calendar"], jwtSecret))
	mux.HandleFunc("/profile", protectedPage(pageTemplates["profile"], jwtSecret))
	mux.HandleFunc("/employees", protectedPage(pageTemplates["employees"], jwtSecret))

	mux.HandleFunc("/api/active-users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}
		data, err := parseAuthToken(r, jwtSecret)
		if err != nil {
			http.Error(w, "Требуется авторизация", http.StatusUnauthorized)
			return
		}
		activeUsers.touch(data)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(activeUsers.list())
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		data, err := parseAuthToken(r, jwtSecret)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		activeUsers.touch(data)
		data.CloudURL = os.Getenv("NEXTCLOUD_URL")

		if execErr := tmpl.Execute(w, data); execErr != nil {
			log.Printf("Ошибка рендера шаблона: %v", execErr)
			http.Error(w, "Ошибка рендера страницы", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requester, err := parseAuthToken(r, jwtSecret)
		if err != nil {
			http.Error(w, "Требуется авторизация", http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodGet {
			users, err := userService.GetUsers(r.Context())
			if err != nil {
				log.Printf("Ошибка при загрузке пользователей: %v", err)
				http.Error(w, "Не удалось загрузить список сотрудников", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(users); err != nil {
				log.Printf("Ошибка отправки списка пользователей: %v", err)
			}
			return
		}

		if r.Method == http.MethodPost {
			if requester.Role != "admin" {
				http.Error(w, "Недостаточно прав", http.StatusForbidden)
				return
			}

			var req struct {
				FullName string `json:"full_name"`
				Email    string `json:"email"`
				Password string `json:"password"`
				Role     string `json:"role"`
			}

			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Ошибка чтения данных", http.StatusBadRequest)
				return
			}

			role := req.Role
			if role == "" {
				role = "employee"
			}
			if role != "employee" && role != "admin" && role != "guest" {
				http.Error(w, "Недопустимая роль", http.StatusBadRequest)
				return
			}
			if role == "admin" && requester.Role != "admin" {
				http.Error(w, "Недостаточно прав", http.StatusForbidden)
				return
			}

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			if err != nil {
				log.Printf("Ошибка хэширования пароля: %v", err)
				http.Error(w, "Внутренняя ошибка", http.StatusInternalServerError)
				return
			}

			user := &service.User{
				Email:        req.Email,
				FullName:     req.FullName,
				PasswordHash: string(hashedPassword),
				Role:         role,
			}

			if err := userService.AddUser(r.Context(), user, req.Password); err != nil {
				log.Printf("Ошибка при добавлении пользователя: %v", err)
				http.Error(w, "Не удалось создать сотрудника", http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
			return
		}

		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		requester, err := parseAuthToken(r, jwtSecret)
		if err != nil {
			http.Error(w, "Требуется авторизация", http.StatusUnauthorized)
			return
		}
		if requester.Role != "admin" {
			http.Error(w, "Недостаточно прав", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}

		id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/users/"))
		if err != nil || id < 1 {
			http.Error(w, "Некорректный идентификатор сотрудника", http.StatusBadRequest)
			return
		}
		if id == requester.UserID {
			http.Error(w, "Нельзя удалить собственную учетную запись", http.StatusBadRequest)
			return
		}
		if err := userService.DeleteUser(r.Context(), id, requester.UserID); err != nil {
			log.Printf("Ошибка удаления пользователя %d: %v", id, err)
			http.Error(w, "Не удалось удалить сотрудника", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/api/tasks", func(w http.ResponseWriter, r *http.Request) {
		user, err := parseAuthToken(r, jwtSecret)
		if err != nil {
			http.Error(w, "Требуется авторизация", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			tasks, err := taskService.GetVisible(r.Context(), user.UserID)
			if err != nil {
				log.Printf("Ошибка загрузки задач: %v", err)
				http.Error(w, "Не удалось загрузить задачи", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(tasks)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			DueDate     string `json:"due_date"`
			Visibility  string `json:"visibility"`
			Status      string `json:"status"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "Некорректный запрос", http.StatusBadRequest)
			return
		}
		req.Title = strings.TrimSpace(req.Title)
		if req.Title == "" || len([]rune(req.Title)) > 200 {
			http.Error(w, "Название задачи обязательно", http.StatusBadRequest)
			return
		}
		dueDate, err := time.Parse("2006-01-02", req.DueDate)
		if err != nil {
			http.Error(w, "Неверный формат даты", http.StatusBadRequest)
			return
		}
		if req.Visibility != "private" && req.Visibility != "public" {
			req.Visibility = "private"
		}
		if req.Status == "" {
			req.Status = "todo"
		}

		task := &models.Task{
			Title:       req.Title,
			Description: strings.TrimSpace(req.Description),
			DueDate:     dueDate,
			Visibility:  req.Visibility,
			Status:      req.Status,
			CreatedBy:   user.UserID,
		}
		if err := taskService.Create(r.Context(), task); err != nil {
			log.Printf("Ошибка создания задачи: %v", err)
			http.Error(w, "Не удалось создать задачу", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(task)
	})

	mux.HandleFunc("/api/tasks/", func(w http.ResponseWriter, r *http.Request) {
		_, err := parseAuthToken(r, jwtSecret)
		if err != nil {
			http.Error(w, "Требуется авторизация", http.StatusUnauthorized)
			return
		}

		idStr := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
		id, err := strconv.Atoi(idStr)
		if err != nil || id < 1 {
			http.Error(w, "Некорректный ID задачи", http.StatusBadRequest)
			return
		}

		if r.Method == http.MethodDelete {
			if err := taskService.DeleteTask(r.Context(), id); err != nil {
				log.Printf("Ошибка удаления задачи %d: %v", id, err)
				http.Error(w, "Не удалось удалить задачу", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method == http.MethodPatch {
			var req struct {
				Status string `json:"status"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Некорректный запрос", http.StatusBadRequest)
				return
			}

			if req.Status != "todo" && req.Status != "in_progress" && req.Status != "done" {
				http.Error(w, "Недопустимый статус", http.StatusBadRequest)
				return
			}

			if err := taskService.UpdateStatus(r.Context(), id, req.Status); err != nil {
				log.Printf("Ошибка обновления статуса %d: %v", id, err)
				http.Error(w, "Не удалось обновить статус", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	portsToTry := []string{port}
	if os.Getenv("PORT") == "" {
		portsToTry = append(portsToTry, "8081", "8082")
	}

	wrappedMux := securityHeaders(mux)

	for i, currentPort := range portsToTry {
		addr := ":" + currentPort
		fmt.Printf("Пробую запуск сервера на http://localhost:%s\n", currentPort)

		err = http.ListenAndServe(addr, wrappedMux)
		if err != nil && isAddressInUse(err) && i < len(portsToTry)-1 {
			log.Printf("Порт %s занят, переключаюсь на %s", currentPort, portsToTry[i+1])
			continue
		}

		break
	}

	if err != nil {
		fmt.Println("Критическая ошибка при запуске сервера:", err)
	}
}
