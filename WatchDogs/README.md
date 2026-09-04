# WatchDogs

![Watchdogs](./0image0.png)

**Watch from above, Gather everything, Own the surface**

A modular reconnaissance engine for subdomain monitoring, vulnerability scanning, and attack surface mapping. Built for bug bounty hunters and red teams.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        WATCHDOGS COMPONENTS                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─ RECON TOOLS ─┐   ┌─ ENGINE (SERVER) ────┐   ┌─ CLIENTS (LAPTOP) ─┐ │
│  │               │   │                       │   │                    │ │
│  │ subfinder     │──►│  CLI Daemon           │   │  Web (Next.js) ◄──│──│── :3000
│  │ crtsh         │   │  ./watchdogs          │   │  TUI ◄────────────│──│── WATCHDOGS_API_URL
│  │ httpx         │   │  4-phase pipeline     │   │  CLI ◄────────────│──│── api-config.json
│  │ naabu         │   │  perpetual monitoring  │   │                    │ │
│  │ nuclei        │   │                       │   │  SSH Tunnel also   │ │
│  │ gowitness     │   │  MongoDB ◄───────────►│   │  works for all:    │ │
│  │               │   │  (watchdogs db)       │   │  ssh -L 8080:...   │ │
│  └───────────────┘   │                       │   └────────────────────┘ │
│                       │  Go API Server ◄─────│                          │
│                       │  ./apisrv :8080      │                          │
│                       └───────────────────────┘                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## The 4 Components

### 1. CLI Daemon (`./watchdogs`)

The core orchestrator. Runs the full recon pipeline:

```bash
# Build
go build -o watchdogs .

# Run as daemon (perpetual monitoring)
./watchdogs

# Or run commands directly
./watchdogs breads                    # List all targets
./watchdogs breads http uber          # Subdomains for uber
./watchdogs breads http all uber      # Full details with tech/ports
./watchdogs breads cve uber           # Nuclei findings
./watchdogs gungnir                   # CT log hot subdomains
```

**4-Phase Scan Pipeline:**

| Phase | Tooling | Output | Timeout |
|-------|---------|--------|---------|
| 1. Discovery | subfinder, findomain, crtsh, anubisdb, hackerstarget, rapidns, thc | `subdomains` collection | 4h |
| 2. Enrichment | dnsx, httpx, csprecon | `http` collection (status, title, tech, CDN, IP) | 6h |
| 3. Port Scan | naabu (top 100) | `http.ports` | 3h |
| 4. Screenshots | gowitness + chromium | PNGs + DB paths | 2h |

### 2. Go API Server (`./apisrv`)

Standalone HTTP server exposing MongoDB data as JSON REST API:

```bash
# Build
cd cmd/apisrv && go build -o apisrv .

# Run (requires MongoDB on localhost:27017)
./apisrv
# Listens on :8080
```

**All Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Welcome message |
| GET | `/health` | MongoDB ping health check |
| GET | `/targets` | List all target domains → `["walmart","uber",...]` |
| GET | `/breads/http/distinct` | All distinct subdomains from `http` collection |
| GET | `/breads/subs/distinct` | All distinct subdomains from `subdomains` collection |
| GET | `/breads/http/ports` | Subdomains with open ports |
| GET | `/breads/{target}/http` | Subdomains for a target |
| GET | `/breads/{target}/http/all` | Full details: subdomain, title, status_code, ports, technologies |
| GET | `/breads/{target}/http/cve` | Nuclei/CVE findings |
| GET | `/breads/{target}/subs/target` | Raw subdomains from discovery |
| GET | `/breads/{target}/vh-hosts` | Virtual hosts |
| GET | `/hot-breads` | Gungnir CT log subdomains → `["sub1.com","sub2.com",...]` |
| GET | `/providers` | Subdomain discovery providers |

Auth via `X-API-Key` header.

### 3. Web Frontend (`web/`)

Next.js interface with 10 pages:

```bash
cd web
npm install
npm run dev    # :3000, proxy → localhost:8080
```

| Page | Route | Description |
|------|-------|-------------|
| Login | `/login` | Auth (krow / rebel.com(killall)) |
| Programs | `/` | Target list with scope expand |
| Dashboard | `/dashboard` | Stats, charts, recent activity |
| Assets | `/assets` | Asset explorer with smart search |
| Asset Detail | `/asset` | Full asset info + Hunter Assistant |
| Hunting | `/hunting` | Per-asset hunt recommendations |
| Recommended | `/recommended` | Hunt type groupings |
| Timeline | `/timeline` | Activity timeline |
| Gungnir | `/gungnir` | CT log live feed |
| Screenshots | `/screenshots` | Captured pages |
| Settings | `/settings` | Configuration |

**Smart Search Syntax** (Assets page):

| Syntax | Example | Behavior |
|--------|---------|----------|
| `status:200,404` | filter by status codes (OR) |
| `tech:react,next` | filter by technologies (OR) |
| `port:443,8080` | filter by ports (OR) |
| `title:admin` | substring match on title |
| `cdn:cloudflare` | filter by CDN |
| `-domain.com` | exclude subdomains containing this |
| `limit:50` | cap results |
| `new` | last 24h only |
| `api admin` | plain text → full-text AND search |

### 4. TUI (`tui/`)

Terminal interface with 6 views:

```bash
cd tui
go build -o watchdogs-tui .
./watchdogs-tui    # connects to localhost:8080
```

| Key | View | Description |
|-----|------|-------------|
| `1` | Dashboard | Stat cards (8), recent hot-breads, system info |
| `2` | Targets | All targets table, Enter to drill |
| `3` | Assets | Full asset table with smart search (`/` to search) |
| `4` | Detail | Asset detail with tech badges |
| `5` | Gungnir | CT log feed |
| `6` | Settings | API config display |

Search syntax in Assets view same as web.

## Remote Setup

### On the Server (has MongoDB)
```bash
# Required: API server
./apisrv       # :8080

# Optional: daemon for scans
./watchdogs    # perpetual monitoring
```

### On Your Laptop

#### CLI Remote
`Api/api-config.json`:
```json
{
  "enabled": true,
  "port": 8080,
  "vps_address": "your-server-ip",
  "api_key": "Crows0_1e922512-8a0f-453c-e17b-f89b698c1b18_1781166952675"
}
```

```bash
# Run from project root (reads Api/api-config.json)
./watchdogs api breads http all uber
./watchdogs api gungnir
```

#### TUI Remote
```bash
WATCHDOGS_API_URL=http://your-server-ip:8080 \
WATCHDOGS_API_KEY=Crows0_... \
./tui/watchdogs-tui
```

#### Web Remote
Serve web on server (simplest):
```bash
cd web && npm run dev     # :3000 on the server
# Browse to http://your-server-ip:3000
```

Or locally with proxy pointing to server:
```bash
API_URL=http://your-server-ip:8080 npm run dev
```

#### SSH Tunnel (alternative for all)
```bash
ssh -L 8080:localhost:8080 user@your-server
# Then all tools use localhost:8080 normally
```

## MongoDB Collections

| Collection | Document Fields | Populated By |
|------------|----------------|--------------|
| `targets` | `domain`, `name`, `in_scope[]`, `out_of_scope[]` | breads.json |
| `subdomains` | `root_domain`, `subdomain`, `providers[]` | Phase 1 (discovery) |
| `http` | `root_domain`, `subdomain`, `status_code`, `title`, `technologies[]`, `cdn`, `ip`, `cname[]`, `ports[]`, `nuclei_findings[]` | Phase 2-3 (enrichment) |
| `virtual_host` | `root_domain`, `subdomain`, `cname[]` | Phase 2 (csprecon) |
| `hot-breads` | `subdomain`, `root_domain`, `source`, `timestamp` | Gungnir CT monitor |
| `system` | `key`, `value`, `timestamp` | Startup token, heartbeat |

## Requirements

### CLI Tools
```
subfinder  findomain  dnsx  httpx  naabu
nuclei     gowitness  chromium  csprecon  anew
```

### Python (for legacy API, optional)
```bash
pip3 install beautifulsoup4 fastapi uvicorn motor beanie python-dotenv
```

### Go
```bash
go mod tidy
go build -o watchdogs .
go build -o apisrv ./cmd/apisrv/
```

### MongoDB
```bash
docker-compose up -d    # or install natively
```

## Env Files

`.env` (for daemon):
```
Hackerone_Token=token
INTIGRITI_TOKEN=token
NTFY_TOPIC=ntfy-topic
```

`web/.env.local` (for web frontend):
```
NEXT_PUBLIC_API_KEY=Crows0_1e922512-8a0f-453c-e17b-f89b698c1b18_1781166952675
```
