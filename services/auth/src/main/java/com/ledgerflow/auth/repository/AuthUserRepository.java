package com.ledgerflow.auth.repository;

import com.ledgerflow.auth.domain.user.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;


public interface AuthUserRepository extends JpaRepository<AuthUser, UUID> {
    Optional<AuthUser> findByLogin(String login);


}
