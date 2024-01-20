<p align="center">
  <img src="https://github.com/colto1000/webfirewall/assets/33501061/75eae7b5-5db9-4ac3-afa9-01ac9fb88fce" width="250" height="250">
</p>

# webfirewall

_WORK IN PROGRESS_

A IPTables-based firewall with a web application admin frontend, written mostly in Go and HTML.

## Usage
From the root directory of this project, run the command: `go build -o firewall src/firewall/main.go`

...Then, run with: `sudo ./firewall`

Or if using the precompiled binary _(experimental)_, then: **`chmod +x webfirewall_linux_amd64`** and **`./webfirewall_linux_amd64`**

## _**Notes**_

- This project relies on Legacy IPTables modules, so you must first switch to Legacy IPTables if you're not already running it.
  - Run: `sudo update-alternatives --set iptables /usr/sbin/iptables-legacy`
- Some IPTables functionality (like Request Limiting) may or may not work based on what operating system you are running.
- You may have to create an SQL database to fit line 41:
  - `dsn := "webadmin:password12@tcp(localhost:3306)/webfirewall"`
  - **Table Name:** "webfirewall" on SQL server on local machine's **Port 3306**, **Username:** "webadmin", **Password:** "password12".
  - _This will be fixed with implementation of Go's [Embed](https://pkg.go.dev/embed) library._
- This project has been tested with Go v1.21.5 in Ubuntu 22.04.

## Credit:

HTML Template referenced from Stellar by [HTML5 UP](html5up.net).

Logo Created by [OpenAI's](https://openai.com/) ChatGPT and DALL·E.
