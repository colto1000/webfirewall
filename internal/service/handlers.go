package service

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

var (
	//go:embed templates/*
	templates embed.FS
	//go:embed static/*
	static embed.FS
	//go:embed static/images/*
	images embed.FS
)

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func NewWebServer(mw ...echo.MiddlewareFunc) *echo.Echo {
	e := echo.New()
	e.StaticFS("/static", static)
	e.StaticFS("/images", images)
	e.Renderer = &Template{
		templates: template.Must(template.ParseFS(templates, "templates/*.html")),
	}

	// add middleware
	for _, fn := range mw {
		e.Use(fn)
	}

	return e
}

func WithWebServer(e *echo.Echo) Option {
	return func(s *Service) error {
		s.Echo = e
		return nil
	}
}

func WithLogger(l *slog.Logger) Option {
	return func(s *Service) error {
		s.Logger = l
		return nil
	}
}

type Handler struct {
	Method      string
	Path        string
	HandlerFunc echo.HandlerFunc
	MW          []echo.MiddlewareFunc
}

func (svc *Service) AddRoutes() {
	for _, r := range []Handler{
		{Method: echo.GET, Path: "/", HandlerFunc: homePage},
		{Method: echo.GET, Path: "/login", HandlerFunc: loginPage},
		{Method: echo.POST, Path: "/login", HandlerFunc: svc.login},
		{Method: echo.GET, Path: "/logout", HandlerFunc: logout},
		{Method: echo.GET, Path: "/dashboard", HandlerFunc: dashboardPage, MW: []echo.MiddlewareFunc{isAuthenticated}},
		{Method: echo.GET, Path: "/dashboard/logs", HandlerFunc: logsPage, MW: []echo.MiddlewareFunc{isAuthenticated}},
		{Method: echo.GET, Path: "/dashboard/monitor", HandlerFunc: monitorPage, MW: []echo.MiddlewareFunc{isAuthenticated}},
		{Method: echo.GET, Path: "/register", HandlerFunc: registerPage},
		{Method: echo.POST, Path: "/register", HandlerFunc: svc.handleRegistration},
		{Method: echo.POST, Path: "/block-ip", HandlerFunc: svc.blockIPHandler()},
		{Method: echo.POST, Path: "/block-port", HandlerFunc: svc.blockPortHandler()},
		{Method: echo.POST, Path: "/block-service", HandlerFunc: svc.blockServiceHandler()},
		{Method: echo.POST, Path: "/add-request-limit", HandlerFunc: svc.addRequestLimitHandler()},
		{Method: echo.POST, Path: "/add-rate-limit", HandlerFunc: svc.addRateLimitHandler( /*, &ln*/ )},
		{Method: echo.GET, Path: "/list-rules", HandlerFunc: svc.listRules()},
		{Method: echo.GET, Path: "/reset-rules", HandlerFunc: svc.resetRules()},
	} {
		svc.Echo.Add(r.Method, r.Path, r.HandlerFunc, r.MW...)
	}
}

func homePage(c echo.Context) error {
	err := c.Render(http.StatusOK, "home.html", nil)
	if err != nil {
		log.Println("Error rendering home page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

func loginPage(c echo.Context) error {
	err := c.Render(http.StatusOK, "login.html", nil)
	if err != nil {
		log.Println("Error rendering login page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

func registerPage(c echo.Context) error {
	err := c.Render(http.StatusOK, "register.html", nil)
	if err != nil {
		log.Println("Error rendering register page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

func dashboardPage(c echo.Context) error {
	err := c.Render(http.StatusOK, "dashboard.html", nil)
	if err != nil {
		log.Println("Error rendering dashboard page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

func logsPage(c echo.Context) error {
	err := c.Render(http.StatusOK, "logs.html", nil)
	if err != nil {
		log.Println("Error rendering dashboard page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

func monitorPage(c echo.Context) error {
	err := c.Render(http.StatusOK, "monitor.html", nil)
	if err != nil {
		log.Println("Error rendering dashboard page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

/* -- AUTHENTICATION / LOGIN / HASHING MANAGEMENT RELATED FUNCTIONS -- */

var (
	// Key for session encryption. This should be a random, long, and secure key.
	sessionKey = generateSecureKey(32)
	store      = sessions.NewCookieStore([]byte(sessionKey))
)

type User struct {
	Username string `json:"username" validate:"required,alphanum"`
	Password string `json:"password" validate:"required"`
}

// Middleware to check if the user is authenticated
func isAuthenticated(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		session, err := store.Get(c.Request(), "session")
		if err != nil || !session.Values["authenticated"].(bool) {
			return c.Redirect(http.StatusFound, "/login")
		}
		return next(c)
	}
}

func (svc *Service) login(c echo.Context) error {
	// Process login form values
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Validate credentials
	user, err := svc.getUserByUsername(username)
	if err != nil || !CheckPasswordHash(password, user.Password) {
		// Render the login page again with an error message
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{
			"Error": "Invalid Credentials",
		})
	}

	// Validate credentials (this is a simplified example)
	if CheckPasswordHash(password, user.Password) {
		// Set user session
		session, _ := store.Get(c.Request(), "session")
		session.Values["authenticated"] = true
		if err := session.Save(c.Request(), c.Response()); err != nil {
			return err
		}

		// Redirect to dashboard
		return c.Redirect(http.StatusFound, "/dashboard")
	}

	return c.String(http.StatusUnauthorized, "Invalid credentials")
}

func logout(c echo.Context) error {
	session, _ := store.Get(c.Request(), "session")

	// Clearing the session
	session.Options.MaxAge = -1

	err := session.Save(c.Request(), c.Response())
	if err != nil {
		log.Println("Error saving session:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}

	// Redirecting to the home page
	return c.Redirect(http.StatusSeeOther, "/")
}

// func registerUser(c echo.Context) error {
// 	// Bind and validate user input
// 	var user User
// 	if err := c.Bind(&user); err != nil {
// 		return err
// 	}
// 	if err := validate.Struct(user); err != nil {
// 		return c.JSON(http.StatusBadRequest, err.Error())
// 	}

// 	// Proceed with registration
// 	// ...
// }

func (svc *Service) handleRegistration(c echo.Context) error {
	// Extract form data
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Basic validation
	if len(username) < 3 {
		return c.String(http.StatusBadRequest, "Username must be at least 3 characters long.")
	}
	if len(password) < 6 {
		return c.String(http.StatusBadRequest, "Password at least 6 characters long.")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err // or return a more user-friendly error message
	}

	// Create user object
	user := User{
		Username: username,
		Password: string(hashedPassword),
	}

	// Save user to your storage (DB, etc.)
	if err = svc.saveUser(user); err != nil {
		return err // or return a more user-friendly error message
	}

	// Redirect to login page
	return c.Redirect(http.StatusSeeOther, "/login")
}

func (svc *Service) saveUser(user User) error {
	query := `INSERT INTO users (username, password) VALUES (?, ?)`
	_, err := svc.DB.Exec(query, user.Username, user.Password)
	if err != nil {
		return fmt.Errorf("error saving user: %v", err)
	}
	return nil
}

func (svc *Service) getUserByUsername(username string) (user *User, err error) {
	if err := svc.DB.QueryRow("SELECT username, password FROM users WHERE username = ?", username).Scan(&user.Username, &user.Password); errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("user not found")
	} else if err != nil {
		return nil, err
	}

	return user, nil
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPasswordHash compares a hashed password with a plain text password
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateSecureKey(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Error generating secure key: %v", err)
	}

	return base64.StdEncoding.EncodeToString(b)
}
