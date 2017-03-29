package com.auth0.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.stereotype.Component;

@SuppressWarnings("unused")
@Component
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AppConfig extends WebSecurityConfigurerAdapter {
    /**
     * This is your auth0 domain (tenant you have created when registering with auth0 - account name)
     */
    @Value(value = "${com.auth0.domain}")
    private String domain;

    /**
     * This is the client id of your auth0 application (see Settings page on auth0 dashboard)
     */
    @Value(value = "${com.auth0.clientId}")
    private String clientId;

    /**
     * This is the client secret of your auth0 application (see Settings page on auth0 dashboard)
     */
    @Value(value = "${com.auth0.clientSecret}")
    private String clientSecret;

    @Autowired
    private AuthenticationManager manager;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable();

        Auth0AuthenticationFilter filter = new Auth0AuthenticationFilter(manager);
        filter.setEntryPoint(new Auth0EntryPoint());
//        http.addFilterAfter(new Auth0AuthenticationFilter(), BasicAuthenticationFilter.class);
        http.authorizeRequests()
                .antMatchers("/callback", "/login").permitAll()
                .antMatchers("/portal/**").authenticated()
                .anyRequest().denyAll();
//         Auth0 library will will control session management explicitly - not spring security
        http.addFilterAfter(filter, SecurityContextPersistenceFilter.class);
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);

    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

//    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
//    @Override
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(new Auth0AuthenticationProvider());
//    }

    public String getDomain() {
        return domain;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }
}
