package service

import (
	"net/http"

	"github.com/coreos/go-iptables/iptables"
	"github.com/labstack/echo/v4"
)

func NewIPTables() (*iptables.IPTables, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}

	return ipt, nil
}

func WithIPTables(table string) Option {
	return func(s *Service) error {
		ipt, err := NewIPTables()
		if err != nil {
			return err
		}
		s.IPTables = ipt
		s.iptablesDBTable = table

		return nil
	}
}

type IPTablesRules struct {
	Chain string   `json:"chain"`
	Rules []string `json:"rules"`
}

func (svc *Service) listRules() echo.HandlerFunc {
	return func(c echo.Context) error {

		// List all chains in the filter table
		chains, err := svc.IPTables.ListChains("filter")
		if err != nil {
			return err
		}

		var allRules []IPTablesRules

		// Iterate over each chain and list rules
		for _, chain := range chains {
			rules, err := svc.IPTables.List("filter", chain)
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

func (svc *Service) resetRules() echo.HandlerFunc {
	return func(c echo.Context) error {
		// Clear all rules
		if err := svc.IPTables.ClearAll(); err != nil {
			return err
		}

		// ... then, continue with listing all rules
		chains, err := svc.IPTables.ListChains("filter")
		if err != nil {
			return err
		}

		var allRules []IPTablesRules

		// Iterate over each chain and list rules
		for _, chain := range chains {
			rules, err := svc.IPTables.List("filter", chain)
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

func (svc *Service) blockIP(ip string, srcdst string) error {
	if srcdst == "source" {
		return svc.IPTables.
			AppendUnique(svc.iptablesDBTable, "INPUT", "-s", ip, "-j", "DROP")
	}

	// if srcdst == "destination"
	return svc.IPTables.
		AppendUnique(svc.iptablesDBTable, "OUTPUT", "-d", ip, "-j", "DROP")
}

func (svc *Service) blockPort(port string, protocol string, srcdst string) error {
	if srcdst == "source" {
		return svc.IPTables.
			AppendUnique(svc.iptablesDBTable, "INPUT", "-p", protocol, "--dport", port, "-j", "DROP")
	}

	// if srcdst == "destination"
	return svc.IPTables.
		AppendUnique(svc.iptablesDBTable, "OUTPUT", "-p", protocol, "--dport", port, "-j", "DROP")
}

func (svc *Service) blockService(port string) error {
	if err := svc.IPTables.
		AppendUnique(svc.iptablesDBTable, "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP"); err != nil {
		return err
	}

	if err := svc.IPTables.
		AppendUnique(svc.iptablesDBTable, "INPUT", "-p", "udp", "--dport", port, "-j", "DROP"); err != nil {
		return err
	}

	return nil
}

func (svc *Service) addRequestLimit(ip string, sec string, hits string) error {
	return svc.IPTables.
		AppendUnique(svc.iptablesDBTable, "INPUT", "-s", ip, "-m", "state", "--state", "NEW", "-m", "recent", "--update", "--seconds", sec, "--hitcount", hits, "-j", "DROP")
}

// func addRateLimit( ip string, rate string) error {
// 	return ipt.Append(tableName, "INPUT", "-s", ip, "-m", "limit", "--limit", rate, "-j", "ACCEPT")
// }

func (svc *Service) blockIPHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		ip := c.FormValue("ip")
		srcdst := c.FormValue("srcdst")

		if err := svc.blockIP(ip, srcdst); err != nil {
			return c.String(http.StatusInternalServerError, "Failed to block IP")
		}

		return c.String(http.StatusOK, "IP blocked successfully")
	}
}

func (svc *Service) blockPortHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		port := c.FormValue("port")
		protocol := c.FormValue("protocol")
		srcdst := c.FormValue("srcdst")

		if err := svc.blockPort(port, protocol, srcdst); err != nil {
			return c.String(http.StatusInternalServerError, "Failed to block port")
		}

		return c.String(http.StatusOK, "Port blocked successfully")
	}
}

func (svc *Service) blockServiceHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		port := c.FormValue("port")
		if err := svc.blockService(port); err != nil {
			return c.String(http.StatusInternalServerError, "Failed to block service")
		}

		return c.String(http.StatusOK, "Service blocked successfully")
	}
}

func (svc *Service) addRequestLimitHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		ip := c.FormValue("ip")
		sec := c.FormValue("sec")
		hits := c.FormValue("hits")

		if err := svc.IPTables.
			AppendUnique(svc.iptablesDBTable, "INPUT", "-m", "state", "--state", "NEW", "-m", "recent", "--set"); err != nil {
			return err
		}

		if err := svc.addRequestLimit(ip, sec, hits); err != nil {
			return c.String(http.StatusInternalServerError, "Failed to create request limit")
		}

		return c.String(http.StatusNotImplemented, "Request limit added successfully")
	}

}

func (svc *Service) addRateLimitHandler( /*, ln *net.Listener*/ ) echo.HandlerFunc {
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
