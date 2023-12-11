package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"

	// "os"
	"path/filepath"

	"github.com/coreos/go-iptables/iptables"
	"github.com/go-playground/validator/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

var (
	// Key for session encryption. This should be a random, long, and secure key.
	sessionKey = generateSecureKey(32)
	store      = sessions.NewCookieStore([]byte(sessionKey))
)

type User struct {
	Username string `json:"username" validate:"required,alphanum"`
	Password string `json:"password" validate:"required"`
}

// Define a template renderer
// func renderer(templates string) echo.Renderer {
// 	return &TemplateRenderer{
// 		templates: template.Must(template.ParseGlob(templates)),
// 	}
// }

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

var validate *validator.Validate
var db *sql.DB

func init() {
	var err error
	// Replace with your database source name
	dsn := "webadmin:password12@tcp(localhost:3306)/webfirewall"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
}

func main() {

	// Create a new Echo instance
	e := echo.New()

	// Handle template (webpage) files
	templatesPath := filepath.Join("cmd", "templates", "*.html")
	fmt.Println("templatesPath: ", templatesPath)
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob(templatesPath)),
	}
	e.Renderer = renderer

	// Serve static files -- try to implement filepath.Join better here
	e.Static("/static", filepath.Join("cmd", "static"))
	// e.Static("/static", "cmd/static")

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Pages (Routes)
	e.GET("/", homePage)
	e.GET("/login", loginPage)
	e.POST("/login", login)
	e.GET("/dashboard", dashboardPage, isAuthenticated)
	e.GET("/register", registerPage)
	e.POST("/register", handleRegistration)

	// Start server
	e.Logger.Fatal(e.Start(":8082"))

	// Create a new IPTables instance
	ipt, err := iptables.New()
	if err != nil {
		log.Fatalf("Error creating iptables instance: %v", err)
	}

	// Example: List rules in the filter table and INPUT chain
	rules, err := ipt.List("filter", "INPUT")
	if err != nil {
		log.Fatalf("Error listing iptables rules: %v", err)
	}

	// Print the rules
	for _, rule := range rules {
		fmt.Println(rule)
	}

	validate = validator.New()

}

// Handler
// func homeHandler(c echo.Context) error {
// 	return c.Render(http.StatusOK, "home.html", nil)
// }

func homePage(c echo.Context) error {
	// return c.File("home.html")
	// print a message to the console indicating pwd
	// fmt.Println("pwd: ", os.Getenv("PWD"))

	// return c.Render(http.StatusOK, "home.html", nil)

	err := c.Render(http.StatusOK, "home.html", nil)
	if err != nil {
		log.Println("Error rendering home page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

func loginPage(c echo.Context) error {
	// Render login template
	// return c.File("login.html")

	err := c.Render(http.StatusOK, "login.html", nil)
	if err != nil {
		log.Println("Error rendering login page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

func registerPage(c echo.Context) error {
	// return c.File("register.html")

	err := c.Render(http.StatusOK, "register.html", nil)
	if err != nil {
		log.Println("Error rendering register page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

func dashboardPage(c echo.Context) error {
	// return c.File("dashboard.html")

	err := c.Render(http.StatusOK, "dashboard.html", nil)
	if err != nil {
		log.Println("Error rendering dashboard page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
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

func login(c echo.Context) error {
	// Process login form values
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Validate credentials
	user, err := getUserByUsername(username) // Implement this function to retrieve user data
	if err != nil {
		// Handle error, user not found
	}

	// Validate credentials (this is a simplified example)
	if CheckPasswordHash(password, user.Password) {
		// Set user session
		session, _ := store.Get(c.Request(), "session")
		session.Values["authenticated"] = true
		session.Save(c.Request(), c.Response())

		// Redirect to dashboard
		return c.Redirect(http.StatusFound, "/dashboard")
	}

	return c.String(http.StatusUnauthorized, "Invalid credentials")
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

func handleRegistration(c echo.Context) error {
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
	err = saveUser(user) // Implement this function according to your storage solution
	if err != nil {
		return err // or return a more user-friendly error message
	}

	// Redirect to login page or return success message
	return c.Redirect(http.StatusSeeOther, "/login")
}

func saveUser(user User) error {
	query := `INSERT INTO users (username, password) VALUES (?, ?)`
	_, err := db.Exec(query, user.Username, user.Password)
	if err != nil {
		return fmt.Errorf("error saving user: %v", err)
	}
	return nil
}

func getUserByUsername(username string) (User, error) {
	var user User
	err := db.QueryRow("SELECT username, password FROM users WHERE username = ?", username).Scan(&user.Username, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return User{}, fmt.Errorf("user not found")
		}
		return User{}, err
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
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Error generating secure key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
