# HomeCloud Relay Server

High-performance WebSocket relay server for secure file transfer between PC and Android clients.

**Built with:** Java + Netty + JWT Authentication + Admin Panel

## Features

### Core Features
- **JWT Authentication**: Secure token-based authentication with configurable expiration
- **Device Pairing**: QR code-based pairing with E2E encryption support
- **File Transfer**: Efficient binary file transfer with chunked streaming
- **Heartbeat System**: PING/PONG every 30 seconds for connection health
- **Concurrent & Scalable**: Netty async event loop, thread-safe structures

### Admin Panel 🆕
- **Web UI**: http://your-server:8080/admin
- **Real-time Monitoring**: Live statistics, connected clients, active pairs
- **Pair Management**: View, delete pairs (password-protected)
- **Client Management**: View, disconnect clients
- **Log Viewer**: Filter, search logs (INFO/WARN/ERROR/SECURITY)
- **Authentication**: Session-based with 30-minute timeout

### Security 🔒
- **Path Traversal Protection**: Filename validation and sanitization
- **File Size Limits**: Maximum 500 MB per file
- **Input Validation**: UserIds, file sizes, all inputs sanitized
- **Rate Limiting**: Per-user transfer limits (5 concurrent)
- **Security Logging**: All attack attempts logged and visible in admin panel

---

## How It Works

- **Token Endpoint:**
    - `POST /api/token` with `{ "userId": "..." }` returns a JWT for that user.
- **WebSocket Endpoint:**
    - Connect with `Authorization: Bearer <token>` header.
    - Supports registration, pairing, file transfer, file list sync, and other commands between paired clients.

- **File Storage:**
    - Uploaded files are stored in the `uploads` directory in the server's working directory.

---

## Running the Server

### Requirements

- Docker (recommended) **OR** Java 21+ and Gradle

### Docker (Recommended)

1. Build and run the container:
   ```sh
   docker build -t homecloud-relay .
   docker run -p 8080:8080 --env JWT_SECRET=yourSuperSecretKey homecloud-relay
   ```

    - The server will listen on port 8080 by default.
    - Optionally override the port via the `PORT` environment variable.

### Manual (Java/Gradle)

1. Build the fat-jar:
   ```sh
   ./gradlew shadowJar
   ```
2. Run:
   ```sh
   export JWT_SECRET=yourSuperSecretKey
   java -jar build/libs/<your-jar>-all.jar
   ```

    - Replace `<your-jar>` with actual jar name.

### Environment Variables

#### Required for Production:
- `JWT_SECRET` — **REQUIRED!** Secret key for signing JWT tokens (min 32 chars)

#### Admin Panel:
- `ADMIN_USERNAME` — Admin username (default: `admin`)
- `ADMIN_PASSWORD` — Admin password (default: `admin123`) **⚠️ CHANGE THIS!**

#### Optional:
- `PORT` — Port to listen on (default: 8080)
- `UPLOADS_DIR` — Upload directory (default: `uploads`)
- `CONSOLE_LOGGING` — Enable console logs (default: `true`, set `false` to use web UI only)

---

## Security Features

### Authentication & Authorization
- **JWT Tokens**: Configurable expiration (1 hour to 30 days max)
- **Secure Pairing**: QR code-based with E2E encryption
- **Per-Pair Isolation**: Each pair is isolated, no cross-pair access

### Input Validation
- **Path Traversal Protection**: Filenames validated and sanitized
- **File Size Limits**: Maximum 500 MB per file
- **UserId Validation**: Only alphanumeric characters allowed (max 100 chars)

### Attack Prevention
- **Security Logging**: All attack attempts logged with SECURITY level
- **Rate Limiting**: 5 concurrent transfers per user
- **Heartbeat System**: Automatic cleanup of dead connections

### Admin Security
- **Password Protection**: Critical operations require admin password
- **Session Timeout**: 30 minutes of inactivity
- **Action Logging**: All admin actions logged

⚠️ **Production Checklist:**
1. Set strong `JWT_SECRET` (32+ characters)
2. Change `ADMIN_USERNAME` and `ADMIN_PASSWORD`
3. Use HTTPS (not HTTP)
4. Set `CONSOLE_LOGGING=false` to reduce log exposure

---

## Example API Usage

- **Get token:**
  ```http
  POST /api/token
  Content-Type: application/json

  { "userId": "your-user-id" }
  ```
  Returns: JWT token in response body.

- **WebSocket Connect:**
    - Connect to `ws://<host>:8080` with header `Authorization: Bearer <token>`.
    - Exchange pairing and file commands as per client protocol.

---

## Admin Panel

### Access
**URL**: `http://your-server:8080/admin`

**Default Credentials**:
- Username: `admin`
- Password: `admin123`

⚠️ **Change credentials via environment variables before deploying!**

### Features
- **Dashboard**: Real-time server statistics (clients, pairs, files, uptime)
- **Pairs Management**: 
  - View all pairs (active/offline)
  - View pair statistics (files transferred, data, uptime)
  - Delete specific pair (requires password)
  - Delete ALL pairs (requires password)
- **Client Management**:
  - View connected clients with IP addresses
  - Disconnect specific client
- **Log Viewer**:
  - View last 1000 logs
  - Filter by level (INFO/WARN/ERROR/SECURITY/ADMIN)
  - Search logs
  - Clear logs
  - Color-coded by severity

### API Endpoints

**Authentication:**
- `POST /admin/api/login` - Login with username/password
- `POST /admin/api/logout` - Logout

**Statistics:**
- `GET /admin/api/stats` - Server statistics

**Pairs:**
- `GET /admin/api/pairs` - List all pairs
- `POST /admin/api/pairs/delete` - Delete specific pair (requires password)
- `POST /admin/api/pairs/delete-all` - Delete all pairs (requires password)

**Clients:**
- `GET /admin/api/clients` - List connected clients
- `POST /admin/api/clients/disconnect` - Disconnect client

**Logs:**
- `GET /admin/api/logs?level=INFO&search=text` - Get filtered logs
- `POST /admin/api/logs/clear` - Clear all logs

---

## License

MIT
