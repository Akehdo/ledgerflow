package com.ledgerflow.auth.domain.user;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_users")
public class AuthUser {
    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "login", nullable = false, unique = true, length = 255)
    private String login;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private UserStatus status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;


    protected AuthUser() {
        // JPA only
    }

    public static AuthUser create(String login, String passwordHash) {
        AuthUser user = new AuthUser();
        user.id = UUID.randomUUID();
        user.login = login;
        user.passwordHash = passwordHash;
        user.status = UserStatus.ACTIVE;
        user.createdAt = Instant.now();
        user.updatedAt = Instant.now();

        return user;
    }


    public UUID getId() {
        return id;
    }

    public String getLogin() {
        return login;
    }

    public UserStatus getStatus() {
        return status;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    @PreUpdate
    void onUpdate(){
        this.updatedAt = Instant.now();
    }
}
