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
	"os"

	// "reflect"

	"path/filepath"

	"github.com/coreos/go-iptables/iptables"
	"github.com/go-playground/validator/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

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

	// Open a log file
	logFile, err := os.OpenFile("output.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer logFile.Close()

	// Redirect output to the file
	log.SetOutput(logFile)
	os.Stdout = logFile
	os.Stderr = logFile

	// Create a new Echo and IPTables instance
	e := echo.New()
	ipt, err := iptables.New()

	// Handle template (webpage) files
	templatesPath := filepath.Join("src", "templates", "*.html")
	log.Println("templatesPath: ", templatesPath)
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob(templatesPath)),
	}
	e.Renderer = renderer

	// Serve static files -- try to implement filepath.Join better here
	e.Static("/static", filepath.Join("src", "static"))
	e.Static("/images", filepath.Join("src", "images"))
	// e.Static("/static", "src/static")

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Pages (Routes)
	e.GET("/", homePage)
	e.GET("/login", loginPage)
	e.POST("/login", login)
	e.GET("/logout", logout)
	e.GET("/dashboard", dashboardPage, isAuthenticated)
	e.GET("/register", registerPage)
	e.POST("/register", handleRegistration)

	e.POST("/block-ip", blockIPHandler(ipt))
	e.POST("/block-port", blockPortHandler(ipt))
	e.POST("/request-limit", addRequestLimitHandler(ipt))
	e.POST("/rate-limit", addRateLimitHandler(ipt))
	e.GET("/list-rules", listRules(ipt))

	e.GET("/index", indexPage)
	e.GET("/generic", genericPage)
	e.GET("/elements", elementsPage)

	// Start server
	e.Logger.Fatal(e.Start(":8082"))

	// // Create a new IPTables instance
	// ipt, err := iptables.New()
	// if err != nil {
	// 	log.Fatalf("Error creating iptables instance: %v", err)
	// }

	// // Example: List rules in the filter table and INPUT chain
	// rules, err := ipt.List("filter", "INPUT")
	// if err != nil {
	// 	log.Fatalf("Error listing iptables rules: %v", err)
	// }

	// // Print the rules
	// for _, rule := range rules {
	// 	fmt.Println(rule)
	// }

	validate = validator.New()

}

/* -- IPTABLES FUNCTIONS -- */

const tableName = "filter"

// func contains(list []string, value string) bool {
// 	for _, val := range list {
// 		if val == value {
// 			return true
// 		}
// 	}
// 	return false
// }

// func createInputToPortFilter(ipt *iptables.IPTables) {
// 	chain := "INPUT"
// 	list, err := ipt.ListChains(tableName)
// 	log.Printf("chain list:%v", list)
// 	if err != nil {
// 		log.Printf("ListChains of Initial failed: %v", err)
// 	}
// 	isExists, err := ipt.Exists(tableName, chain, "-j", "port_jump")
// 	if !isExists {
// 		err = ipt.Append(tableName, chain, "-j", "port_jump")
// 		if err != nil {
// 			log.Printf("Append Input To Port Jump: %v\n", err)
// 		}
// 	}

// }
// func createMacBasedProtFilter(ipt *iptables.IPTables, port uint32) {
// 	chain := ProtFilterChainName
// 	err := ipt.ClearChain(tableName, chain)
// 	if err != nil {
// 		log.Printf("ClearChain (of non-empty) failed: %v\n", err)
// 	}
// 	err = ipt.Insert(tableName, chain, 1, "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", MacFilterChainName)
// 	err = ipt.Insert(tableName, chain, 1, "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", MacFilterChainName)
// }

// func createMacFilter(ipt *iptables.IPTables) {
// 	chain := MacFilterChainName
// 	err := ipt.ClearChain(tableName, chain)
// 	if err != nil {
// 		log.Printf("ClearChain (of non-empty) failed: %v", err)
// 	}
// 	// put a simple rule in
// 	err = ipt.Insert(tableName, chain, 1, "-m", "mac", "--mac-source", "00:0F:EA:91:04:08", "-j", "ACCEPT")
// 	if err != nil {
// 		log.Printf("Append failed: %v", err)
// 	}
// 	err = ipt.Append(tableName, chain, "-j", "DROP")
// 	if err != nil {
// 		log.Printf("Append failed: %v", err)
// 	}

// }

type IPTablesRules struct {
	Chain string   `json:"chain"`
	Rules []string `json:"rules"`
}

func listRules(ipt *iptables.IPTables) echo.HandlerFunc {
	return func(c echo.Context) error {

		// rules, err := ipt.List(tableName, "INPUT")
		// if err != nil {
		// 	return err
		// }

		// return c.JSON(http.StatusOK, rules)

		// List all chains in the filter table
		chains, err := ipt.ListChains("filter")
		if err != nil {
			return err
		}

		var allRules []IPTablesRules

		// Iterate over each chain and list rules
		for _, chain := range chains {
			rules, err := ipt.List("filter", chain)
			if err != nil {
				return err
			}

			allRules = append(allRules, IPTablesRules{
				Chain: chain,
				Rules: rules,
			})
		}

		return c.JSON(http.StatusOK, allRules)
	}
}

func blockIP(ipt *iptables.IPTables, ip string, srcdst string) error {
	if srcdst == "source" {
		return ipt.Append(tableName, "INPUT", "-s", ip, "-j", "DROP")
	} else { // if srcdst == "destination"
		return ipt.Append(tableName, "OUTPUT", "-d", ip, "-j", "DROP")
	}
}

func blockPort(ipt *iptables.IPTables, port string, protocol string, srcdst string) error {
	if srcdst == "source" {
		return ipt.Append(tableName, "INPUT", "-p", protocol, "--dport", port, "-j", "DROP")
	} else { // if srcdst == "destination"
		return ipt.Append(tableName, "OUTPUT", "-p", protocol, "--dport", port, "-j", "DROP")
	}
}

func addRequestLimit(ipt *iptables.IPTables, ip string) error {
	return ipt.AppendUnique(tableName, "INPUT", "-s", ip, "-m", "state", "--state", "NEW", "-m", "recent", "--update", "--seconds", "60", "--hitcount", "100", "-j", "DROP")
}

func addRateLimit(ipt *iptables.IPTables, ip string, rate string) error {
	return ipt.Append(tableName, "INPUT", "-s", ip, "-m", "limit", "--limit", rate, "-j", "ACCEPT")
}

func blockIPHandler(ipt *iptables.IPTables) echo.HandlerFunc {
	return func(c echo.Context) error {
		ip := c.FormValue("ip")
		srcdst := c.FormValue("srcdst")

		err := blockIP(ipt, ip, srcdst)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to block IP")
		}

		return c.String(http.StatusOK, "IP blocked successfully")
	}
}

func blockPortHandler(ipt *iptables.IPTables) echo.HandlerFunc {
	return func(c echo.Context) error {
		port := c.FormValue("port")
		protocol := c.FormValue("protocol")
		srcdst := c.FormValue("srcdst")

		err := blockPort(ipt, port, protocol, srcdst)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to block port")
		}

		return c.String(http.StatusOK, "Port blocked successfully")
	}
}

func addRequestLimitHandler(ipt *iptables.IPTables) echo.HandlerFunc {
	return func(c echo.Context) error {
		ip := c.FormValue("ip")

		ipt.AppendUnique(tableName, "INPUT", "-m", "state", "--state", "NEW", "-m", "recent", "--set")

		err := addRequestLimit(ipt, ip)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to create request limit")
		}

		return c.String(http.StatusOK, "Request limit added successfully")
	}

}

func addRateLimitHandler(ipt *iptables.IPTables) echo.HandlerFunc {
	return func(c echo.Context) error {
		ip := c.FormValue("ip")
		rate := c.FormValue("rate")

		err := addRateLimit(ipt, ip, rate)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to create rate limit")
		}

		return c.String(http.StatusOK, "Rate limit added successfully")
	}

}

/* -- WEBPAGE RELATED FUNCTIONS -- */

func elementsPage(c echo.Context) error {
	err := c.Render(http.StatusOK, "elements.html", nil)
	if err != nil {
		log.Println("Error rendering index page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

func genericPage(c echo.Context) error {
	err := c.Render(http.StatusOK, "generic.html", nil)
	if err != nil {
		log.Println("Error rendering index page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

func indexPage(c echo.Context) error {
	err := c.Render(http.StatusOK, "index.html", nil)
	if err != nil {
		log.Println("Error rendering index page:", err)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	return nil
}

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

	// if !isAuthenticated(c) {
	//     // Render the access denied page
	//     return c.Render(http.StatusForbidden, "denied.html", nil)
	// }

	err := c.Render(http.StatusOK, "dashboard.html", nil)
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

func login(c echo.Context) error {
	// Process login form values
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Validate credentials
	user, err := getUserByUsername(username) // Implement this function to retrieve user data
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
		session.Save(c.Request(), c.Response())

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
