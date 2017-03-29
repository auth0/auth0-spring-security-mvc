package com.auth0.example;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class Auth0AuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //Check existing authentication
        final Authentication existingAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuthentication != null && existingAuthentication.isAuthenticated()) {
            return existingAuthentication;
        }

        //Use new authentication
        TokenAuthentication tokenAuth = (TokenAuthentication) authentication;
        tokenAuth.setAuthenticated(true);
//        final ServletRequestAttributes servletReqAttr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
//        final HttpServletRequest req = servletReqAttr.getRequest();
        //FIXME: Tokens should be already verified (by the com.auth0.example.CallbackController)
        return tokenAuth;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return TokenAuthentication.class.isAssignableFrom(clazz);
    }
}
