package com.auth0.example;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class TokenAuthentication extends AbstractAuthenticationToken {

    private final String accessToken;
    private final String idToken;

    public TokenAuthentication(String accessToken, String idToken) {
        super(null);
        this.accessToken = accessToken;
        this.idToken = idToken;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }


}
