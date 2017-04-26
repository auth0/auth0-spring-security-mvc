package com.auth0.example.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@SuppressWarnings("unused")
@Component
public class Auth0AuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //Check existing authentication
        final Authentication existingAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuthentication != null && existingAuthentication.isAuthenticated()) {
            return existingAuthentication;
        }
        //Return the new one
        return authentication;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return TokenAuthentication.class.isAssignableFrom(clazz);
    }
}
