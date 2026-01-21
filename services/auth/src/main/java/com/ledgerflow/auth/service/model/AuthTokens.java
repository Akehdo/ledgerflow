package com.ledgerflow.auth.service.model;

public class AuthTokens {
    private final String accessToken;
    private final String refreshToken;

    public AuthTokens(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public String accessToken(){
        return accessToken;
    }

    public String refreshToken(){
        return refreshToken;
    }
}
