plugins {
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.netty:netty-all:4.1.109.Final")
    implementation("org.json:json:20240303")
    implementation("com.auth0:java-jwt:4.4.0")
    implementation("com.google.code.gson:gson:2.10.1")
}

tasks {
    shadowJar {
        manifest {
            attributes(
                "Main-Class" to "org.example.UnifiedServer"
            )
        }
    }
}