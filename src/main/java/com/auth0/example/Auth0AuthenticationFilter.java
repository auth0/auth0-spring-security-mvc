package com.auth0.example;

import com.auth0.SessionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Auth0AuthenticationFilter extends GenericFilterBean {

    private AuthenticationManager manager;
    private AuthenticationEntryPoint entryPoint;

    public Auth0AuthenticationFilter(AuthenticationManager manager) {
        this.manager = manager;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain next) throws IOException, ServletException {
        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse res = (HttpServletResponse) response;
        String accessToken = (String) SessionUtils.get(req, "accessToken");
        String idToken = (String) SessionUtils.get(req, "idToken");
        boolean hasTokens = accessToken != null || idToken != null;
        if (!hasTokens) {
            next.doFilter(request, response);
            return;
        }

        try {
            TokenAuthentication tokenAuth = new TokenAuthentication(accessToken, idToken);
            final Authentication authResult = manager.authenticate(tokenAuth);
            SecurityContextHolder.getContext().setAuthentication(authResult);
        } catch (AuthenticationException exception) {
            SecurityContextHolder.clearContext();
            entryPoint.commence(req, res, exception);
        }
    }

    public AuthenticationEntryPoint getEntryPoint() {
        return entryPoint;
    }

    public void setEntryPoint(final AuthenticationEntryPoint entryPoint) {
        this.entryPoint = entryPoint;
    }
}
