plugins {
    java
    application
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.java-websocket:Java-WebSocket:1.5.3")
}

application {
    mainClass.set("org.example.RelayWebSocketServer") // <-- замени на свой полный путь
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = application.mainClass.get()
    }
    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith(".jar") }
            .map { zipTree(it) }
    })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
