plugins {
    java
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.netty:netty-all:4.1.109.Final")
    implementation("org.json:json:20240303")
    implementation("com.auth0:java-jwt:4.4.0")
}