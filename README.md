# Curator

**Every conclusion, traced to its evidence.**

AI-assisted security investigation for SOC analysts: correlates alerts and logs,
reconstructs attack timelines, maps them to MITRE ATT&CK, and links every generated
sentence to the raw log line that supports it.

- `system_design.md`: architecture, data model, API contracts, conventions
- `DESIGN.md`: interface specification, authoritative for anything visual
- `datasets/SCHEMA_NOTES.md`: what the APT29 dataset actually contains, as verified

**Status: Step 2 of 7.** The APT29 events are normalized to OCSF in Postgres, next to
ATT&CK techniques with local embeddings, the dataset's ground truth, and a hash-chained
audit log. No dedup, correlation, or AI yet.

---

## Setup on Kali Linux (rootless Docker)

### 1. Install Docker Engine, Compose v2, and the rootless extras

Kali is Debian-based; use Docker's Debian `bookworm` repository.

```sh
sudo apt update
sudo apt install -y ca-certificates curl make openssl uidmap dbus-user-session slirp4netns
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin \
  docker-compose-plugin docker-ce-rootless-extras
```

Compose must be the v2 plugin (`docker compose`), not the legacy `docker-compose` binary.

### 2. Switch to rootless mode

```sh
# Your user needs subordinate ID ranges (Kali normally creates them).
grep "^$(whoami):" /etc/subuid /etc/subgid

# Stop the rootful daemon so the setup tool doesn't refuse, and so nothing talks to it by accident.
sudo systemctl disable --now docker.service docker.socket

dockerd-rootless-setuptool.sh install
systemctl --user enable --now docker
sudo loginctl enable-linger "$(whoami)"     # keep the daemon running after logout

docker context use rootless                 # created by the setup tool
```

Optional but recommended: membership in the `docker` group is root-equivalent on a
rootful socket. Once you are on rootless, remove it with `sudo gpasswd -d "$(whoami)" docker`.

Confirm:

```sh
docker info --format '{{.SecurityOptions}}'   # must include name=rootless
docker compose version                        # v2.x or later
```

### 3. Start Curator

```sh
make up
```

On the first run this creates `api/.env` from `.env.example` with a random
`POSTGRES_PASSWORD` and links `./.env` to it, builds the images (the API image bakes in
the embedding model), starts all three containers, and returns once all three pass their
healthchecks.

- Web: <http://localhost:5173> (shows `connected` when the API and database are up)
- API: <http://localhost:8000/health>

### 4. Load the data

```sh
make seed
```

1. Downloads whatever is missing from `datasets/`, about 111 MB, each file checked
   against a pinned SHA-256: the APT29 event zips and emulation plan from OTRF
   Security-Datasets (commit `d9d40ef`), and the ATT&CK Enterprise 19.2 STIX bundle.
2. Loads the 697 active ATT&CK techniques and embeds them locally with
   `BAAI/bge-small-en-v1.5`.
3. Streams all 783,367 APT29 events through the parser into `events`, then loads the
   127 ground-truth rows from the emulation plan.

On an 8-core laptop the first load takes about 8 minutes: 2 to embed techniques, 5 to
load events. The database ends up around 3.2 GB (the Docker volume, with WAL, around
4.4 GB), so check `df -h` first. The load is idempotent: a second run inserts nothing.
Every load is recorded in the audit chain.

`make seed-offline` runs the same loaders in a container whose only network has no route
to the internet (it checks that before starting). It proves nothing is downloaded at
runtime once `datasets/` is populated.

To check every stored raw event byte-for-byte against the source files:

```sh
docker compose exec curator-api python -m curator.ingest.seed apt29 --verify-raw
```

Add `ANTHROPIC_API_KEY` to `api/.env` before Step 4. Nothing calls the Anthropic API
yet, and `DRY_RUN=true` stays the default until you change it.

---

## Make targets

| Target              | What it does                                                          |
| ------------------- | --------------------------------------------------------------------- |
| `make up`           | Build and start everything, detached; waits until all three are healthy |
| `make down`         | Stop and remove containers; the database volume is kept               |
| `make reset`        | `down`, **delete the database volume**, `up`; re-runs `db/init/`      |
| `make seed`         | Load ATT&CK techniques, then the APT29 events and ground truth        |
| `make seed-offline` | The same, in a container with no route to the internet               |
| `make eval`         | Run the accuracy harness (not implemented yet; Step 6)                |
| `make logs`         | Follow logs from all three services                                   |
| `make shell-api`    | Bash inside `curator-api`                                             |
| `make psql`         | `psql` inside `curator-db`, using the container's own credentials     |

## API

| Method and path      | Returns                                                            |
| -------------------- | ------------------------------------------------------------------ |
| `GET /health`        | `{"status":"ok","db":true,"version":"0.1.0"}`                      |
| `POST /seed`         | body `{"dataset":"apt29"}`; `{"events":N,"skipped":M,"sources":{...}}` |
| `GET /audit/verify`  | `{"valid":true,"rows":N,"broken_at":null}`                         |

## Services

| Service       | Image / base              | Host port          | Notes                                              |
| ------------- | ------------------------- | ------------------ | -------------------------------------------------- |
| `curator-db`  | `pgvector/pgvector:pg16`  | none               | volume `pgdata`; `db/init/` runs on first boot       |
| `curator-api` | `python:3.11-slim`        | `127.0.0.1:8000`   | FastAPI + uvicorn `--reload`; `./api` and `./datasets` mounted |
| `curator-web` | `node:20-alpine`          | `127.0.0.1:5173`   | Vite dev server; `./web` mounted                   |

## Notes

- **Ports bind to 127.0.0.1 only**, so the dev stack isn't exposed on shared (e.g.
  hackathon) Wi-Fi. To reach it from another device, change the `ports:` entries in
  `docker-compose.yml` to drop the `127.0.0.1:` prefix.
- **Postgres has no host port.** Kali's own PostgreSQL (used by `msfdb`) often holds
  5432. Use `make psql`.
- **`api/.env` is the only real env file** and is gitignored. `curator-api` reads all
  of it. `curator-db` receives only `POSTGRES_USER`, `POSTGRES_PASSWORD` and
  `POSTGRES_DB`, which Compose fills in from `./.env`, a symlink to `api/.env` that
  `make up` creates.
- **`db/init/` runs only on an empty volume.** For schema changes, and for changes to
  `POSTGRES_*` in `api/.env`, run `make reset`.
- **`datasets/` is gitignored**, apart from `SCHEMA_NOTES.md`. Loaders download into it
  and verify every file's SHA-256 before use.
- **No model downloads at runtime.** The embedding model is fetched once, at image
  build, into `/opt/fastembed`; the image then sets `HF_HUB_OFFLINE=1`.
- **Web dependencies** live in the image, not on the host. `make up` passes
  `--renew-anon-volumes`, so the container picks up changes to `package.json`.
- Under rootless Docker, container root maps to your user, so anything the containers
  write into `./api`, `./web` or `./datasets` stays owned by you.

## Troubleshooting

| Symptom                                               | Cause and fix                                                            |
| ----------------------------------------------------- | ------------------------------------------------------------------------ |
| `required variable POSTGRES_USER is missing a value`  | `./.env` or `api/.env` does not exist yet. Run `make up` once.           |
| `permission denied ... /var/run/docker.sock`          | The CLI is pointed at the rootful socket. Run `docker context use rootless`. |
| Page shows `database unreachable`                     | The API is up but can't reach Postgres. `make logs`, check `curator-db`. |
| `password authentication failed` after editing `api/.env` | The volume was initialised with the old password. `make reset`.      |
| `port is already allocated` on 8000 or 5173           | Something else is listening: `ss -ltnp \| grep -E ':(8000\|5173)'`.        |
| `ChecksumError` during `make seed`                    | A file in `datasets/` differs from the pinned original. Delete it and re-run. |
