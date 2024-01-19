<p align="center">
  <img src="https://github.com/colto1000/webfirewall/assets/33501061/75eae7b5-5db9-4ac3-afa9-01ac9fb88fce" width="250" height="250">
</p>

# webfirewall

_WORK IN PROGRESS_

A IPTables-based firewall with a web application admin frontend, written mostly in Go and HTML.

## Usage
From the parent directory, run the command: **`go run cmd/main.go`**

Or if using the precompiled binary _(experimental)_, then: **`chmod +x webfirewall_linux_amd64`** and **`./webfirewall_linux_amd64`**

## _**Notes**_

_This project relies on Legacy IPTables modules, so you must first run `sudo update-alternatives --set iptables /usr/sbin/iptables-legacy` if you are not already running a Legacy version of IPTables._

_This project has been tested with Go v1.21.5 in Ubuntu 22.04_

## Credit:

HTML Template referenced from Stellar by [HTML5 UP](html5up.net).

Logo Created by [OpenAI's](https://openai.com/) ChatGPT and DALL·E.
