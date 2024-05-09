<p align="center">
  <img src="https://github.com/colto1000/webfirewall/assets/33501061/75eae7b5-5db9-4ac3-afa9-01ac9fb88fce" width="250" height="250">
</p>

# webfirewall

_WORK IN PROGRESS_

A IPTables-based firewall with a web application admin frontend, written mostly in Go and HTML.

## Usage
**From the root directory of this project, run the command: `go build -o firewall main.go`**

**...Then, run with: `sudo ./firewall`**

**Connect to the service at http://localhost:8082**

## _Notes_

- _You may try using the precompiled binary _(experimental)_: `chmod +x webfirewall_linux_amd64` and `sudo ./webfirewall_linux_amd64`_
- This project relies on Legacy IPTables modules, so you must first switch to Legacy IPTables if you're not already running it.
  - Run: `sudo update-alternatives --set iptables /usr/sbin/iptables-legacy`
- Some IPTables functionality (like Request Limiting) may or may not work based on what operating system you are running.
- You may have to create an SQL database to fit:
  - "webadmin:password12@tcp(localhost:3306)/webfirewall"
  - **Table Name:** "webfirewall" on SQL server on local machine's **Port 3306**, **Username:** "webadmin", **Password:** "password12".
- Install the required iptables modules, if not already installed. 
  - `sudo apt-get install xtables-addons-common xtables-addons-dkms`
- This project has been tested with Go v1.21.5 in Ubuntu 22.04.

## _Todo:_

- [X] Implement Golang embed
- [ ] Implement GeoLite Database functionality
- [ ] Fix log rotation/archival system
- [X] Add System/Network monitoring
- [X] Add log viewing webpage
- [ ] Log more than just echo output
- [ ] Major visual redesign
- [ ] SSL/TLS to encrypt traffic
- [ ] Host the site on a Pi or cloud server

## Credit:

HTML Template referenced from Stellar by [HTML5 UP](html5up.net).

Logo Created by [OpenAI's](https://openai.com/) ChatGPT and DALL·E.
