package com.auth0.spring.security.mvc;

import com.auth0.Auth0AuthorityStrategy;
import com.auth0.jwt.Algorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.filter.OrderedRequestContextFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

/**
 * Holds the default configuration for the library
 * Applications are expected to extend this configuration on as-needed basis
 *
 * Extend this configuration in your own subclass and override specific functions to apply your own
 * behaviour as required eg. to apply custom authentication / authorization strategies to your application endpoints
 */
@Configuration
@EnableWebSecurity
@ConditionalOnProperty(prefix = "auth0", name = "defaultAuth0WebSecurityEnabled")
public class Auth0Config extends WebSecurityConfigurerAdapter {

    /**
     * This is your auth0 domain (tenant you have created when registering with auth0 - account name)
     */
    @Value(value = "${auth0.domain}")
    protected String domain;

    /**
     * This is the issuer of the JWT Token (typically full URL of your auth0 tenant account
     * eg. https://{tenant_name}.auth0.com/
     */
    @Value(value = "${auth0.issuer}")
    protected String issuer;

    /**
     * This is the client id of your auth0 application (see Settings page on auth0 dashboard)
     */
    @Value(value = "${auth0.clientId}")
    protected String clientId;

    /**
     * This is the client secret of your auth0 application (see Settings page on auth0 dashboard)
     */
    @Value(value = "${auth0.clientSecret}")
    protected String clientSecret;

    /**
     * This is the page / view that users of your site are redirected to on logout. Should start with `/`
     */
    @Value(value = "${auth0.onLogoutRedirectTo}")
    protected String onLogoutRedirectTo;

    /**
     * This is the landing page URL context path for a successful authentication. Should start with `/`
     */
    @Value(value = "${auth0.loginRedirectOnSuccess}")
    protected String loginRedirectOnSuccess;

    /**
     * This is the URL context path for the page to redirect to upon failure. Should start with `/`
     */
    @Value(value = "${auth0.loginRedirectOnFail}")
    protected String loginRedirectOnFail;

    /**
     * This is the URL context path for the login callback endpoint. Should start with `/`
     */
    @Value(value = "${auth0.loginCallback}")
    protected String loginCallback;

    /**
     * This is the URL pattern to secure a URL endpoint. Should start with `/`
     */
    @Value(value = "${auth0.securedRoute}")
    protected String securedRoute;

    /**
     * The authority strategy being used - can be either ROLES or GROUPS
     * Custom RULES configurable via dashboard may apply ROLES or GROUPS claim on the ID Token
     * whose values are the scope values representing the permissions granted.
     */
    @Value(value = "${auth0.authorityStrategy}")
    protected String authorityStrategy;

    /**
     * This is a boolean value indicating whether the Secret used to verify the JWT is base64 encoded. Default is `true`
     */
    @Value(value = "${auth0.base64EncodedSecret}")
    protected boolean base64EncodedSecret;

    /**
     * This is signing algorithm to verify signed JWT token. Use `HS256` or `RS256`.
     * Default to HS256 for backwards compatibility
     */
    @Value(value = "${auth0.signingAlgorithm:HS256}")
    protected String signingAlgorithm;

    /**
     * This is the path location to the public key stored locally on disk / inside your application War file WEB-INF directory.
     * Should always be set when using `RS256`.
     * Default to empty string as HS256 is default
     */
    @Value(value = "${auth0.publicKeyPath:}")
    protected String publicKeyPath;

    @Autowired
    @SuppressWarnings("SpringJavaAutowiringInspection")
    @Bean(name = "auth0AuthenticationManager")
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * Factory for CORSFilter
     */
    @Bean
    public Auth0CORSFilter simpleCORSFilter() {
        return new Auth0CORSFilter();
    }

    /**
     * Factory for AuthenticationProvider
     */
    @Bean(name = "auth0AuthenticationProvider")
    public Auth0AuthenticationProvider auth0AuthenticationProvider() {
        // First check the authority strategy configured for the API
        if (!Auth0AuthorityStrategy.contains(this.authorityStrategy)) {
            throw new IllegalStateException("Configuration error, illegal authority strategy");
        }
        final Auth0AuthorityStrategy authorityStrategy = Auth0AuthorityStrategy.valueOf(this.authorityStrategy);
        if (Auth0AuthorityStrategy.SCOPE.equals(authorityStrategy)) {
            throw new IllegalStateException("SCOPE authority strategy currently not supported for MVC apps");
        }
        final Auth0AuthenticationProvider authenticationProvider = new Auth0AuthenticationProvider();
        authenticationProvider.setDomain(domain);
        authenticationProvider.setIssuer(issuer);
        authenticationProvider.setClientId(clientId);
        authenticationProvider.setClientSecret(clientSecret);
        authenticationProvider.setSecuredRoute(securedRoute);
        authenticationProvider.setAuthorityStrategy(authorityStrategy);
        authenticationProvider.setBase64EncodedSecret(base64EncodedSecret);
        authenticationProvider.setSigningAlgorithm(Algorithm.valueOf(this.signingAlgorithm));
        authenticationProvider.setPublicKeyPath(this.publicKeyPath);
        return authenticationProvider;
    }

    /**
     * Factory for Auth0AuthenticationEntryPoint
     */
    @Bean(name = "auth0EntryPoint")
    public Auth0AuthenticationEntryPoint auth0AuthenticationEntryPoint() {
        return new Auth0AuthenticationEntryPoint();
    }

    /**
     * Factory for Auth0AuthenticationFilter
     */
    @Bean(name = "auth0Filter")
    public Auth0AuthenticationFilter auth0AuthenticationFilter(final Auth0AuthenticationEntryPoint entryPoint) {
        final Auth0AuthenticationFilter filter = new Auth0AuthenticationFilter();
        filter.setEntryPoint(entryPoint);
        return filter;
    }

    /**
     * Ensure our Filter is only loaded once into Application Context
     */
    @Bean(name = "auth0AuthenticationFilterRegistration")
    public FilterRegistrationBean auth0AuthenticationFilterRegistration(final Auth0AuthenticationFilter filter) {
        final FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(filter);
        filterRegistrationBean.setEnabled(false);
        return filterRegistrationBean;
    }

    /**
     * Factory for OrderedRequestContextFilter
     */
    @Bean
    public OrderedRequestContextFilter requestContextFilter() {
        return new OrderedRequestContextFilter();
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(auth0AuthenticationProvider());
    }

    @Override
    public void configure(final WebSecurity web) throws Exception {
        web.ignoring().antMatchers(HttpMethod.OPTIONS, "/**");
    }

    /**
     * Http Security Configuration
     */
    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        // Disable CSRF for JWT usage
        http.csrf().disable();

        // Add Auth0 Authentication Filter
        http.addFilterAfter(auth0AuthenticationFilter(auth0AuthenticationEntryPoint()), SecurityContextPersistenceFilter.class)
                .addFilterBefore(simpleCORSFilter(), Auth0AuthenticationFilter.class);

        // Apply the Authentication and Authorization Strategies your application endpoints require
        authorizeRequests(http);

        // Auth0 library will will control session management explicitly - not spring security
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
    }

    /**
     * Lightweight default configuration that offers basic authorization checks for authenticated
     * users on secured endpoint, and sets up a Principal user object with granted authorities
     * <p>
     * For simple apps, this is sufficient, however for applications wishing to specify fine-grained
     * endpoint access restrictions, use Role / Group level endpoint authorization etc, then this configuration
     * should be disabled and a copy, augmented with your own requirements provided. See Sample app for example
     * <p>
     * Override this function in subclass to apply custom authentication / authorization
     * strategies to your application endpoints
     */
    protected void authorizeRequests(final HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(securedRoute).authenticated()
                .antMatchers("/**").permitAll();
    }


    public String getDomain() {
        return domain;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getLoginRedirectOnSuccess() {
        return loginRedirectOnSuccess;
    }

    public String getLoginRedirectOnFail() {
        return loginRedirectOnFail;
    }

    public String getOnLogoutRedirectTo() {
        return onLogoutRedirectTo;
    }

    public String getLoginCallback() {
        return loginCallback;
    }

    public String getSecuredRoute() {
        return securedRoute;
    }

    public String getAuthorityStrategy() {
        return authorityStrategy;
    }

    public boolean isBase64EncodedSecret() {
        return base64EncodedSecret;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public String getPublicKeyPath() {
        return publicKeyPath;
    }
}