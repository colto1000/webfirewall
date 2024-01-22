package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4/middleware"

	"github.com/colto1000/webfirewall/internal/service"
)

func main() {
	// read in cmd line args
	dbUsername := flag.String("db-username", "webadmin", "SQL username")
	dbPassword := flag.String("db-password", "password12" /* os.Getenv("DB_PASSWORD") */, "SQL password")
	dbIP := flag.String("db-ip", "localhost", "SQL server IP")
	dbPort := flag.String("db-port", "3306", "SQL server port")
	dbName := flag.String("db-name", "webfirewall", "SQL database name")
	dbTable := flag.String("db-table", "filter", "SQL table name")
	httpPort := flag.Int("http-port", 8082, "HTTP port")
	flag.Parse()

	// Setup logger
	logout := os.Stdout
	logger := slog.New(slog.NewTextHandler(logout, &slog.HandlerOptions{}))

	// create web server
	e := service.NewWebServer(
		middleware.LoggerWithConfig(middleware.LoggerConfig{
			Output: logout,
		}),
		middleware.Recover(),
	)

	// create service
	svc, err := service.New(
		service.WithWebServer(e),
		service.WithDatabaseConn(*dbUsername, *dbPassword, *dbIP, *dbPort, *dbName),
		service.WithIPTables(*dbTable),
		service.WithLogger(logger),
	)
	if err != nil {
		logger.Error("fatal error in setup", slog.String("err", err.Error()))
		os.Exit(1)
	}
	svc.AddRoutes()

	// Start server
	svc.Info("starting server", slog.Int("port", *httpPort))
	if err := svc.Start(fmt.Sprintf(":%d", *httpPort)); err != nil {
		svc.Error("failed to start server", slog.String("err", err.Error()))
	}
}
