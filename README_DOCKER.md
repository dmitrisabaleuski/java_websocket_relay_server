# Docker Deployment Guide for HomeCloud Server

## 🚀 Quick Start

### 1. Build and Start Services

```bash
cd relay_server/java_websocket_relay_server/java_websocket

# Build and start with Docker Compose
docker-compose up -d --build
```

This will:
- Build the Java server container
- Start PostgreSQL container
- Wait for PostgreSQL to be ready
- Start the HomeCloud server
- Create persistent volumes for database and uploads

### 2. Check Logs

```bash
# View all logs
docker-compose logs -f

# View only server logs
docker-compose logs -f server

# View only PostgreSQL logs
docker-compose logs -f postgres
```

### 3. Stop Services

```bash
docker-compose down
```

**Note:** This stops containers but **keeps data** in volumes.

### 4. Stop and Delete All Data

```bash
# Stop containers and delete volumes (WARNING: deletes all data!)
docker-compose down -v
```

---

## 📊 Service Architecture

```
┌─────────────────┐         ┌──────────────┐
│  HomeCloud      │────────▶│ PostgreSQL   │
│  Server         │         │ Database     │
│  (Port 8080)    │         │ (Port 5432)  │
└─────────────────┘         └──────────────┘
        │
        │ WebSocket (wss://...)
        ▼
┌─────────────────┐
│  Android/PC     │
│  Clients        │
└─────────────────┘
```

### Components:

1. **PostgreSQL Container** (`postgres`)
   - Database: `homecloud`
   - User: `postgres`
   - Password: Configurable via environment
   - Data persisted in volume: `postgres_data`

2. **HomeCloud Server Container** (`server`)
   - Java Netty server
   - Port: `8080`
   - Auto-waits for PostgreSQL to be ready
   - Uploads persisted in volume: `uploads_data`

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file (optional):

```bash
# Database password
POSTGRES_PASSWORD=your_secure_password

# JWT secret for token generation
JWT_SECRET=your_random_secret_key

# Admin panel credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_admin_password
```

Default values (for development only):
- `POSTGRES_PASSWORD`: `changeme123`
- `JWT_SECRET`: `changeme456`
- `ADMIN_USERNAME`: `admin`
- `ADMIN_PASSWORD`: `admin123`

### Modify Ports

Edit `docker-compose.yml`:

```yaml
services:
  postgres:
    ports:
      - "YOUR_PORT:5432"  # Change to map different host port
  
  server:
    ports:
      - "YOUR_PORT:8080"  # Change to map different host port
```

---

## 🔧 Troubleshooting

### Server Won't Start

```bash
# Check if PostgreSQL is ready
docker-compose logs postgres | grep "ready to accept connections"

# Check server logs
docker-compose logs server | tail -50

# Restart services
docker-compose restart
```

### Database Connection Issues

```bash
# Test PostgreSQL connection
docker-compose exec postgres psql -U postgres -d homecloud -c "SELECT 1;"

# View database tables
docker-compose exec postgres psql -U postgres -d homecloud -c "\dt"
```

### Reset Everything

```bash
# Stop and delete all data
docker-compose down -v

# Rebuild and start fresh
docker-compose up -d --build
```

---

## 📁 Data Persistence

### Volumes

Data is stored in Docker volumes (persisted on host):

1. `postgres_data`: PostgreSQL database files
   - Location on host: Managed by Docker
   - Contains: All pairs and file transfer history

2. `uploads_data`: Temporary upload files
   - Location on host: Managed by Docker
   - Contains: Files being transferred (deleted after completion)

### Backup Database

```bash
# Backup to file
docker-compose exec postgres pg_dump -U postgres homecloud > backup.sql

# Restore from file
docker-compose exec -T postgres psql -U postgres homecloud < backup.sql
```

---

## 🚢 Production Deployment

For production, set strong passwords and secrets:

```bash
# Generate secure random passwords
export POSTGRES_PASSWORD=$(openssl rand -base64 32)
export JWT_SECRET=$(openssl rand -base64 32)
export ADMIN_PASSWORD=$(openssl rand -base64 16)

# Start services
docker-compose up -d --build
```

### Recommended Production Setup:

1. Use external PostgreSQL (e.g., AWS RDS, DigitalOcean)
   - Update `DATABASE_URL` in `docker-compose.yml`
   - Remove `postgres` service from compose

2. Use reverse proxy (nginx, Caddy)
   - SSL/TLS termination
   - Rate limiting
   - Load balancing

3. Enable monitoring
   - Prometheus + Grafana
   - Health checks

---

## 🔗 URLs

- **WebSocket Server**: `ws://localhost:8080`
- **Admin Panel**: `http://localhost:8080/admin`
- **Health Check**: `http://localhost:8080/health`
- **Token API**: `http://localhost:8080/api/token`

---

## 📝 Logs

```bash
# Follow logs in real-time
docker-compose logs -f

# Search logs
docker-compose logs server | grep "ERROR"

# Export logs
docker-compose logs > server.log
```

