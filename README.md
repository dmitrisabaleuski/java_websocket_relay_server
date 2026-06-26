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

---

## 4. Deployment Instructions (AWS & Cloudflare R2)

To deploy the HomeCloud Relay Server in a production environment using AWS and Cloudflare R2, follow these steps:

### Step 1: Cloudflare R2 Configuration (Storage Backend)
1. Log in to your Cloudflare Dashboard and navigate to **R2**.
2. Click **Create Bucket**, name it (e.g., `homecloud-storage`), and click create.
3. Click **Manage R2 API Tokens** on the right sidebar.
4. Click **Create API Token**:
   * Set permissions to **Edit** (Read/Write access is required for S3 PUT, GET, and DELETE).
   * Scope: Restrict to your bucket or allow all.
   * Click **Create Token**.
5. Save the generated credentials:
   * **Access Key ID**
   * **Secret Access Key**
   * **Endpoint URL** (should look like `https://<account-id>.r2.cloudflarestorage.com`)

### Step 2: AWS EC2 Instance Setup (Compute & Signaling Server)
1. Go to AWS Console -> **EC2** -> **Launch Instance**.
2. Choose a Linux AMI (Ubuntu Server 24.04 LTS is recommended). A `t3.micro` or `t3.small` instance is sufficient.
3. Configure **Security Group** inbound rules:
   * Allow port `22` (SSH) for administration.
   * Allow port `8080` (or whichever port you assign to Netty WebSocket).
   * Allow port `443` (if setting up SSL/TLS reverse proxy via NGINX).

### Step 3: Database Provisioning (PostgreSQL)
You can either run PostgreSQL in a Docker container on the same EC2 instance (e.g., via `docker-compose`) or use AWS RDS PostgreSQL for managed high availability.
For local storage setup, the server falls back to SQLite automatically if PostgreSQL environment variables are omitted, but PostgreSQL is highly recommended for production clustering.

### Step 4: Server Configuration (Environment Variables)
Configure the following environment variables in your deployment environment (e.g., in a `.env` file or a systemd service file on the EC2 VM):

| Variable Name | Description | Example Value |
| --- | --- | --- |
| `PORT` | WebSocket listening port (default: 8080) | `8080` |
| `DB_URL` | PostgreSQL JDBC connection URL | `jdbc:postgresql://<rds-endpoint>:5432/homecloud` |
| `DB_USER` | PostgreSQL username | `postgres` |
| `DB_PASSWORD` | PostgreSQL password | `securepassword` |
| `S3_ENDPOINT` | Cloudflare R2 Endpoint | `https://<account-id>.r2.cloudflarestorage.com` |
| `S3_ACCESS_KEY` | R2 Access Key ID | `6c2...5b3` |
| `S3_SECRET_KEY` | R2 Secret Access Key | `5a7...d6c` |
| `S3_BUCKET` | R2 Bucket Name | `homecloud-storage` |
| `S3_REGION` | S3 Region code | `auto` |

### Step 5: Run the Server
You can run the server directly or containerized:

#### Option A: Running via Docker Compose (Recommended)
1. Install Docker & Docker-Compose on your EC2 instance.
2. Transfer the server files to your EC2 instance.
3. Run the container:
   ```bash
   docker-compose up -d --build
   ```

#### Option B: Running via Java Jar
1. Build the production shadow jar locally:
   ```bash
   ./gradlew shadowJar
   ```
2. Copy the resulting `.jar` file to the EC2 instance:
   ```bash
   java -jar build/libs/java_websocket-1.0.0.jar
   ```
   *(Ensure all environment variables listed in Step 4 are exported prior to running the jar)*.

