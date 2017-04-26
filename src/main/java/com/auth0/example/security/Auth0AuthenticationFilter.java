package com.auth0.example.security;

import com.auth0.SessionUtils;
import com.auth0.jwt.JWT;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Auth0AuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationEntryPoint entryPoint;

    public Auth0AuthenticationFilter(AuthenticationEntryPoint entryPoint) {
        this.entryPoint = entryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain next) throws ServletException, IOException {
        String accessToken = (String) SessionUtils.get(req, "accessToken");
        String idToken = (String) SessionUtils.get(req, "idToken");
        boolean hasTokens = accessToken != null || idToken != null;
        if (!hasTokens) {
            next.doFilter(req, res);
            return;
        }

        try {
            TokenAuthentication tokenAuth = new TokenAuthentication(JWT.decode(idToken));
            SecurityContextHolder.getContext().setAuthentication(tokenAuth);
            next.doFilter(req, res);
        } catch (AuthenticationException exception) {
            SecurityContextHolder.clearContext();
            entryPoint.commence(req, res, exception);
        }
    }
}
