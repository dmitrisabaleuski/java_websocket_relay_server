plugins {
    application
    java
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.java-websocket:Java-WebSocket:1.5.3")
    implementation("com.auth0:java-jwt:4.4.0")
    implementation("com.sparkjava:spark-core:2.9.4")
    implementation("org.json:json:20240303")
}

application {
    mainClass.set("org.example.Main")
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