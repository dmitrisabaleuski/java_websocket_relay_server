# HomeCloud Relay Server

This is a high-performance relay server for secure file transfer and synchronization between PC and Android clients, built with Netty (Java) and JWT authentication.

## Features

- **JWT-secured authentication:** Only authenticated clients can connect and exchange data.
- **Pairing logic:** Each client pair (PC–Android) is isolated; file transfers and commands are only routed within a pair.
- **WebSocket-based file transfer:** Supports large files (chunked transfer), real-time commands, and file list synchronization.
- **Concurrent and scalable:** Uses Netty's async event loop model with thread-safe structures.
- **Docker-ready:** Optimized for containerized deployment with multi-stage Dockerfile.

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

- `PORT` — Port to listen on (default: 8080)
- `JWT_SECRET` — Secret key for signing JWT tokens (default: hardcoded in code, **should be overridden in production**)

---

## Security Notes

- **Always use a strong JWT secret** and set it via environment variable (`JWT_SECRET`) in production!
- Only authenticated clients can pair and exchange files.
- Each pair is isolated; no cross-pair file access.
- All file transfers are point-to-point via WebSocket (binary/text frames).

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

## License

MIT
