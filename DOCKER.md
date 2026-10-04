# nScout with Docker

nScout can run as a Docker Compose stack with the React UI, FastAPI backend, and MongoDB.

## Requirements

- Docker Desktop on Windows/macOS, or Docker Engine + Compose on Linux
- About 1 GB free disk space for build layers and dependencies

## Start nScout

From the repository root:

```bash
docker compose up --build -d
```

Then open:

```text
http://localhost:8001
```

View logs:

```bash
docker compose logs -f nscout
```

Stop the stack:

```bash
docker compose down
```

MongoDB data is kept in the `nscout-mongo` Docker volume. To also erase saved MongoDB data:

```bash
docker compose down -v
```

## AI key (optional)

Create a `.env` file beside `docker-compose.yml`:

```env
EMERGENT_LLM_KEY=your_key_here
```

The core packet analyzer works without this optional integration.

## Packet capture notes

The container receives `NET_RAW` and `NET_ADMIN`, which are needed for packet capture on Linux. The interfaces visible to nScout are the interfaces visible inside the container.

- **Simulated traffic and PCAP import/export:** portable and suitable for Docker Desktop or Linux.
- **Container-network capture:** supported when the Docker host/kernel permits it.
- **Full host-interface capture:** best on native Linux using host networking. Uncomment `network_mode: host` in `docker-compose.yml` and remove the `ports` mapping.
- **Windows + Docker Desktop:** Linux containers run behind Docker's VM/network layer, so they do not have the same direct access to Windows/Npcap interfaces as the native `nScout.exe`. Use the Windows release when direct Windows host packet capture is required.

## Build only

```bash
docker build -t nscout:local .
```

Run the image with an existing MongoDB service by setting `MONGO_URL` and `DB_NAME`.
