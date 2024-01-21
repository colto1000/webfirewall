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
	"path/filepath"

	"github.com/coreos/go-iptables/iptables"
	"github.com/go-playground/validator/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

const (
	tableName     = "filter"            // IPTables table name
	port          = ":8082"             // echo web server port
	logfile       = "output.log"        // logfile for program output
	maxLogSize    = 10 * 1024 * 1024    // 10 MB
	logfileBackup = "output_backup.log" // backup when logfile gets too big
	SQLdb         = "webfirewall"       // SQL database name
	SQLusr        = "webadmin"          // SQL username
	SQLpw         = "password12"        // SQL plaintext password
	SQLip         = "localhost"         // SQL server IP (e.g. localhost)
	SQLport       = "3306"              // SQL server port (e.g. 3306)
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

	dsn := SQLusr + ":" + SQLpw + "@tcp(" + SQLip + ":" + SQLport + ")/" + SQLdb // Alternative:  dsn := "webadmin:password12@tcp(localhost:3306)/webfirewall"
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

	// Save for later outputting to console
	consoleOutput := os.Stdout

	// Open a log file
	logCheck, err := os.Stat(logfile)
	if err != nil {
		log.Printf("Unable to check log file: %v", err)
	} else if logCheck.Size() >= maxLogSize {
		err := os.Rename(logfile, logfileBackup)
		if err != nil {
			log.Fatalf("Error renaming log file to backup: %v", err)
		} else {
			log.Printf("Log file max exceeded, moved logfile to backup: %v", logfileBackup)
		}
	}
	logger, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer logger.Close()

	if _, err := logger.WriteString("\n\n"); err != nil { // creating some blank space between program runs
		log.Println(err)
	}

	// Redirect output to the file
	log.SetOutput(logger)
	os.Stdout = logger
	os.Stderr = logger

	// Create a new Echo and IPTables instance
	e := echo.New()
	ipt, err := iptables.New()

	// Setup for use in rate limiting, later...
	// ln, err := net.Listen("tcp", port)
	// if err != nil {
	// 	log.Fatalf("Failed to listen: %v", err)
	// }

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
	e.POST("/block-service", blockServiceHandler(ipt))
	e.POST("/add-request-limit", addRequestLimitHandler(ipt))
	e.POST("/add-rate-limit", addRateLimitHandler(ipt /*, &ln*/))
	e.GET("/list-rules", listRules(ipt))
	e.GET("/reset-rules", resetRules(ipt))

	// Start server
	fmt.Fprintf(consoleOutput, "Server starting on localhost%v...\nRemaining output logged to %v\n", port, logfile)
	e.Logger.Fatal(e.Start(port))
	//fmt.Fprintf(consoleOutput, "Server started on localhost:", port, "\n")  // can't get this to print, maybe echo takes over console output?

	validate = validator.New()

}

/* -- IPTABLES FUNCTIONS -- */

type IPTablesRules struct {
	Chain string   `json:"chain"`
	Rules []string `json:"rules"`
}

func listRules(ipt *iptables.IPTables) echo.HandlerFunc {
	return func(c echo.Context) error {

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

func resetRules(ipt *iptables.IPTables) echo.HandlerFunc {
	return func(c echo.Context) error {

		ipt.ClearAll() // Clear all rules

		// ... then, continue with listing all rules

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
		return ipt.AppendUnique(tableName, "INPUT", "-s", ip, "-j", "DROP")
	} else { // if srcdst == "destination"
		return ipt.AppendUnique(tableName, "OUTPUT", "-d", ip, "-j", "DROP")
	}
}

func blockPort(ipt *iptables.IPTables, port string, protocol string, srcdst string) error {
	if srcdst == "source" {
		return ipt.AppendUnique(tableName, "INPUT", "-p", protocol, "--dport", port, "-j", "DROP")
	} else { // if srcdst == "destination"
		return ipt.AppendUnique(tableName, "OUTPUT", "-p", protocol, "--dport", port, "-j", "DROP")
	}
}

func blockService(ipt *iptables.IPTables, port string) error {
	err := ipt.AppendUnique(tableName, "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP")
	if err != nil {
		return err
	}

	err = ipt.AppendUnique(tableName, "INPUT", "-p", "udp", "--dport", port, "-j", "DROP")
	if err != nil {
		return err
	}

	return err
}

func addRequestLimit(ipt *iptables.IPTables, ip string, sec string, hits string) error {
	return ipt.AppendUnique(tableName, "INPUT", "-s", ip, "-m", "state", "--state", "NEW", "-m", "recent", "--update", "--seconds", sec, "--hitcount", hits, "-j", "DROP")
}

// func addRateLimit(ipt *iptables.IPTables, ip string, rate string) error {
// 	return ipt.Append(tableName, "INPUT", "-s", ip, "-m", "limit", "--limit", rate, "-j", "ACCEPT")
// }

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

func blockServiceHandler(ipt *iptables.IPTables) echo.HandlerFunc {
	return func(c echo.Context) error {
		port := c.FormValue("port")

		err := blockService(ipt, port)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to block service")
		}

		return c.String(http.StatusOK, "Service blocked successfully")
	}
}

func addRequestLimitHandler(ipt *iptables.IPTables) echo.HandlerFunc {
	return func(c echo.Context) error {
		ip := c.FormValue("ip")
		sec := c.FormValue("sec")
		hits := c.FormValue("hits")

		ipt.AppendUnique(tableName, "INPUT", "-m", "state", "--state", "NEW", "-m", "recent", "--set")

		err := addRequestLimit(ipt, ip, sec, hits)
		if err != nil {

			return c.String(http.StatusInternalServerError, "Failed to create request limit")
		}

		return c.String(http.StatusNotImplemented, "Request limit added successfully")
	}

}

func addRateLimitHandler(ipt *iptables.IPTables /*, ln *net.Listener*/) echo.HandlerFunc {
	return func(c echo.Context) error {
		// limit, err := strconv.ParseInt(c.FormValue("limit")[0:], 10, 64)
		// if err != nil {
		// 	return c.String(http.StatusInternalServerError, "Invalid rate limit, try again with an integer.")
		// }

		// lim := bwlimit.Byte(limit) * bwlimit.Mebibyte

		// *ln = bwlimit.NewListener(*ln, lim, lim)

		// err := addRateLimit(ipt, ip, rate)
		// if err != nil {
		// 	return c.String(http.StatusInternalServerError, "Failed to create rate limit")
		// }

		limit := c.FormValue("limit")

		return c.String(http.StatusOK, "Rate limit is a work in progress. Rule was not added. (Value: "+limit+")")
	}

}

/* -- WEBPAGE RELATED FUNCTIONS -- */

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
