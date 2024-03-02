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
	"os"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"golang.org/x/crypto/bcrypt"
)

var (
	//go:embed templates/*
	templates embed.FS
	//go:embed static/*
	static embed.FS
	// //go:embed static/images/*
	// images embed.FS
)

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func NewWebServer(mw ...echo.MiddlewareFunc) *echo.Echo {
	e := echo.New()
	e.StaticFS("/", static)
	// e.StaticFS("/images", images)
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
		{Method: echo.GET, Path: "/api/stats", HandlerFunc: svc.systemStatsHandler, MW: []echo.MiddlewareFunc{isAuthenticated}},
		{Method: echo.GET, Path: "/api/logs", HandlerFunc: svc.logsHandler, MW: []echo.MiddlewareFunc{isAuthenticated}},
		// {Method: echo.GET, Path: "/elements", HandlerFunc: elementPage},
	} {
		svc.Echo.Add(r.Method, r.Path, r.HandlerFunc, r.MW...)
	}
}

func elementPage(c echo.Context) error {
	err := c.Render(http.StatusOK, "elements.html", nil)
	if err != nil {
		log.Println("Error rendering element page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
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

/* -- SYSTEM RESOURCES -- */

type NetworkStat struct {
	Interface string  `json:"interface"`
	SentMbps  float64 `json:"sentMbps"`
	RecvMbps  float64 `json:"recvMbps"`
}

type SystemStats struct {
	CPU     []float64              `json:"cpu"`
	Memory  *mem.VirtualMemoryStat `json:"memory"`
	Network []NetworkStat          `json:"network"`
}

func (svc *Service) getSystemStats() (*SystemStats, error) {
	stats := &SystemStats{}

	// Fetch CPU stats
	cpuStats, err := cpu.Percent(1*time.Second, false)
	if err != nil {
		return nil, err
	}
	stats.CPU = cpuStats

	// Fetch memory stats
	memoryStats, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}
	stats.Memory = memoryStats

	// Fetch network stats
	networkStats, err := calcNetworkStats()
	if err != nil {
		return nil, err
	}
	stats.Network = networkStats

	return stats, nil
}

var previousStats []net.IOCountersStat
var lastUpdateTime time.Time

func calcNetworkStats() ([]NetworkStat, error) {
	currentStats, err := net.IOCounters(true)
	if err != nil {
		return nil, err
	}

	currentTime := time.Now()
	elapsed := currentTime.Sub(lastUpdateTime).Seconds()
	if elapsed == 0 {
		return nil, nil
	}

	networkData := make([]NetworkStat, 0)
	minLen := min(len(currentStats), len(previousStats))

	for i := 0; i < minLen; i++ {
		sentRate := float64(currentStats[i].BytesSent-previousStats[i].BytesSent) * 8 / (elapsed * 1e6) // Convert to Mbps
		recvRate := float64(currentStats[i].BytesRecv-previousStats[i].BytesRecv) * 8 / (elapsed * 1e6) // Convert to Mbps
		networkData = append(networkData, NetworkStat{
			Interface: currentStats[i].Name,
			SentMbps:  sentRate,
			RecvMbps:  recvRate,
		})
	}

	previousStats = currentStats
	lastUpdateTime = currentTime
	return networkData, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (svc *Service) systemStatsHandler(c echo.Context) error {
	stats, err := svc.getSystemStats()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, stats)
}

func (svc *Service) logsHandler(c echo.Context) error {
	content, err := os.ReadFile("output.log")
	if err != nil {
		fmt.Printf("Failed to read log file: %v", err)
		return c.String(http.StatusInternalServerError, "Unable to read log file")
	}
	return c.String(http.StatusOK, string(content))
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

	// log.Printf("\n *** User: %v // Pass: %v\n", username, password)

	// Validate credentials
	user, err := svc.getUserByUsername(username)
	if err != nil || !CheckPasswordHash(password, user.Password) {
		// Render the login page again with an error message
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{
			"Error": "Invalid Credentials",
		})
	}

	// Validate credentials
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
	user = &User{}
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
