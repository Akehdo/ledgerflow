plugins {
    java
    id("org.springframework.boot") version "4.0.1"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "com.ledgerflow"
version = "0.0.1-SNAPSHOT"
description = "auth"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // === Web / REST ===
    implementation("org.springframework.boot:spring-boot-starter-web")

    // === Security ===
    implementation("org.springframework.boot:spring-boot-starter-security")

    // === JPA / DB ===
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.postgresql:postgresql")
    implementation("org.flywaydb:flyway-core")

    // === Validation ===
    implementation("org.springframework.boot:spring-boot-starter-validation")

    // === JWT ===
    implementation("io.jsonwebtoken:jjwt-api:0.11.5")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.11.5")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.11.5")

    // === Tests ===
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.testcontainers:junit-jupiter:1.19.7")
    testImplementation("org.testcontainers:postgresql:1.19.7")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
