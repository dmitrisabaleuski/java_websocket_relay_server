# HomeCloud Server - Refactored Version

## 🚀 **New Server Architecture**

### **📁 File Structure:**
```
src/main/java/org/example/
├── UnifiedServerRefactored.java    # Main server class
├── UnifiedServerHandler.java       # HTTP/WebSocket handler
├── AdminPanel.java                 # Admin panel and web interface
├── ServerStatistics.java           # Server statistics and metrics
└── utils/
    ├── AdminLogger.java            # Logging system
    └── ServerConfig.java           # Server configuration
```

## 🎯 **How to Run:**

### **1. Build:**
```bash
cd relay_server/java_websocket_relay_server/java_websocket
./gradlew shadowJar
```

### **2. Run:**
```bash
java -jar build/libs/java_websocket_relay_server-all.jar
```

### **3. Access Admin Panel:**
- **URL:** `http://localhost:8080/admin`
- **Login:** `admin`
- **Password:** `admin123`

## 🔧 **Configuration via Environment Variables:**

```bash
# Server port (default: 8080)
export PORT=8080

# Upload directory (default: uploads)
export UPLOADS_DIR=uploads

# JWT secret (default: your-secret-key-change-this-in-production)
export JWT_SECRET=your-secret-key

# Admin username (default: admin)
export ADMIN_USERNAME=admin

# Admin password (default: admin123)
export ADMIN_PASSWORD=admin123
```

## 📊 **Available API Endpoints:**

### **Main:**
- `POST /api/token` - get JWT token
- `GET /health` - server health check

### **Admin Panel:**
- `GET /admin` - login page
- `POST /admin/login` - authentication
- `GET /admin/dashboard` - dashboard

### **Admin API:**
- `GET /api/stats` - server statistics
- `GET /api/clients` - client list
- `GET /api/logs` - server logs

## 🌟 **New Architecture Benefits:**

1. **Modularity** - code is divided into logical components
2. **Readability** - each file is responsible for its own area
3. **Maintainability** - easier to make changes and fixes
4. **Extensibility** - easy to add new features
5. **Testability** - each module can be tested separately

## 🔄 **Migration from Old Version:**

1. **Stop old server**
2. **Run new one:** `java -jar java_websocket_relay_server-all.jar`
3. **All functions work the same!**

## 🚨 **Important:**

- **Old file** `UnifiedServer.java` remains for compatibility
- **New file** `UnifiedServerRefactored.java` - main version
- **All WebSocket connections** work without changes
- **Admin panel** available immediately after startup

## 📝 **Logging:**

All events are logged to console and available through admin panel:
- System events
- Client connections
- Admin actions
- Errors and exceptions

## 🎉 **Ready to Use!**

New server is fully functional and ready to work! 🚀✨
