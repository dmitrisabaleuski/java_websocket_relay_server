# HomeCloud Netty Relay Server

The HomeCloud Netty Relay Server is a high-performance, asynchronous WebSocket control-plane server designed to coordinate pairings and transfers between Android devices and desktop computers.

---

## 1. Purpose of the Application
The server acts as a lightweight communication hub. It manages device registrations, stores client pairing parameters (via PostgreSQL or SQLite), validates JSON Web Tokens (JWT) for secure handshakes, and integrates with S3-compatible cloud storage (Cloudflare R2 or AWS S3) to generate pre-signed upload (PUT) and download (GET) URLs on demand.

---

## 2. Key Components
The server is built using Java and Netty, structured into the following modules:

* **Netty Networking Engine**:
  * `UnifiedServer` & `WebSocketHandler`: Configures the Netty channel pipeline (using SSL handlers, HTTP aggregators, and WebSocket frame decoders) to maintain stable, low-overhead persistent connections with thousands of clients.
* **Storage Integration Module**:
  * `S3Manager`: Integrates with the AWS S3 Java SDK v2. Configures custom endpoint overrides, credentials, and region parameters. Generates pre-signed GET/PUT URLs with strict expiration limits and handles file deletions upon transfer completion.
* **Database & Pairings Module**:
  * `DatabaseManager`: Interfaces with PostgreSQL (production) or SQLite (local debug) to store user pairing tokens, device IDs, and E2E shared secrets, resolving any local state mismatch bugs.
* **Administration & Monitoring**:
  * `AdminWebInterface` & `AdminAuth`: Provides a secure web interface for system administrators to view server statistics, active client connections, and system audit logs.

---

## 3. General Architecture and Workflows

### Stateless File-Transfer Architecture
The Netty server does not process or store any binary file data on its local filesystem. It uses a **stateless file-transfer model**:
1. When a client requests an upload, the server generates a pre-signed S3 PUT URL.
2. When the destination client wants to download, the server generates a pre-signed S3 GET URL.
3. Once the destination client confirms receipt (`CONFIRM_DOWNLOAD`), the server deletes the file from S3 and notifies the sender to free up its upload slot.
This architecture guarantees that the server remains incredibly fast, consumes minimal memory, and cannot be crashed or run out of disk space by large uploads.

### Security and Authentication
* **Token Handshake**: Clients authenticate using JWT tokens obtained via HTTP POST `/api/token`.
* **Isolated Pairings**: The database enforces that only paired devices can request pre-signed links for each other's objects. User files are prefixed with `user_<userId>/` in the S3 bucket to ensure absolute directory isolation.
* **Log Redaction**: All sensitive data, such as JWTs and database connection strings, are automatically redacted from the console and log files (`app.log`) using a custom log filter.
