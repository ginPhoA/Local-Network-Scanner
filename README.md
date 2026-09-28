# Local Network Scanner

A small FastAPI application for an authorised, fixed-scope Nmap scan of the public IPv4 address detected. The page has one button and accepts no scan target, ports, flags, paths, or other configuration from the browser.

## What this does

When **Start scan** is selected, the backend:

1. Retrieves the host Mac's public IP address from `https://api.ipify.org`.
2. Strictly validates that response as IPv4.
3. Runs one TCP Nmap service/version scan of that IP on only ports `21, 22, 25, 53, 80, 443, 3000, 3389, 8080, 8443`.
4. Saves successfully parsed Nmap XML in `results/`.
5. Displays the state and any detected service/version details for each requested port.

Only one scan may run at a time. Failures are shown as a plain-language message and recorded in `Failed_Scans/`.

## Important limitation

This scans the detected **public-facing router/WAN address**, not devices inside the private LAN. It reveals only services exposed to the internet, for example through port forwarding. It does not discover local-network devices or private services.

Only scan systems and network addresses you own or are explicitly authorised to test.

## macOS prerequisites

- Python 3.11 or later (`python3 --version`)
- Nmap, installed manually. With [Homebrew](https://brew.sh/):

  ```bash
  brew install nmap
  ```

The app checks for Nmap when a scan starts and provides a clear message if it is unavailable. It never attempts to install it.

## Windows prerequisites

- Python 3.11 or later
- Nmap installed manually and available in your system PATH

Confirm both from PowerShell:

```powershell
py --version
nmap --version
```

## Setup and run

**macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m app.main
```

**Windows**

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m app.main
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser. 
- The command intentionally binds only to `127.0.0.1`; it is not exposed to other devices on the network.

## Post-Setup

After the initial setup, open terminal and run the following commands.

**macOS**
```bash
source .venv/bin/activate
python -m app.main
```

If any changes are made to `requirements.txt`, run 
```bash 
python -m pip install -r requirements.txt
```

**Windows**
```powershell
.venv\Scripts\python.exe -m app.main
```

If any changes are made to `requirements.txt`, run 
```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Runtime files
- Successful, parsed XML scan files: `results/`
- Failure logs: `Failed_Scans/`

These runtime files are ignored by Git. The `.gitkeep` files simply preserve the empty directories in a fresh checkout.

## Current Limit

This deliberately has no Docker, database, authentication, scan history, AI analysis, comparisons, CI/CD, or target/configuration controls. Those are outside the scope of the project.

Overall, extremely basic.
