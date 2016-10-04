package com.auth0.spring.security.mvc;

import com.auth0.Auth0AuthorityStrategy;
import com.auth0.Auth0User;
import com.auth0.authentication.result.UserIdentity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

/**
 * Implementation of Spring Security UserDetails Object
 * Spring representation of Auth0 UserProfile Object
 */
public class Auth0UserDetails implements UserDetails {

    private static final long serialVersionUID = 2058797193125711681L;

    private String userId;
    private String username;
    private String name;
    private String email;
    private boolean emailVerified;
    private String nickname;
    private String picture;
    private Map<String, Object> extraInfo;
    private List<UserIdentity> identities;
    private ArrayList<GrantedAuthority> authorities;
    private Map<String, Object> userMetadata;

    public Auth0UserDetails(final Auth0User auth0User, final Auth0AuthorityStrategy authorityStrategy) {
        this.userId = auth0User.getUserId();
        if (auth0User.getEmail() != null) {
            this.username = auth0User.getEmail();
        } else if (auth0User.getUserId() != null) {
            this.username = auth0User.getUserId();
        } else {
            this.username = "UNKNOWN_USER";
        }
        this.name = auth0User.getName();
        this.email = auth0User.getEmail();
        if (email != null) {
            emailVerified = auth0User.isEmailVerified();
        }
        this.nickname = auth0User.getNickname();
        this.picture = auth0User.getPicture();
        this.identities = auth0User.getIdentities();
        this.extraInfo = auth0User.getExtraInfo();
        this.userMetadata = auth0User.getUserMetadata();
        setupGrantedAuthorities(auth0User, authorityStrategy);
    }


    /**
     * Currently support Groups and Roles only...
     */
    private void setupGrantedAuthorities(final Auth0User auth0User, final Auth0AuthorityStrategy authorityStrategy) {
        this.authorities = new ArrayList<>();
        if (Auth0AuthorityStrategy.ROLES.equals(authorityStrategy)) {
            if (auth0User.getRoles() != null) {
                try {
                    for (final String role : auth0User.getRoles()) {
                        this.authorities.add(new SimpleGrantedAuthority(role));
                    }
                } catch (ClassCastException e) {
                    e.printStackTrace();
                }
            }
        } else if (Auth0AuthorityStrategy.GROUPS.equals(authorityStrategy)) {
            if (auth0User.getGroups() != null) {
                try {
                    for (final String group : auth0User.getGroups()) {
                        this.authorities.add(new SimpleGrantedAuthority(group));
                    }
                } catch (ClassCastException e) {
                    e.printStackTrace();
                }
            }
        } else if (Auth0AuthorityStrategy.SCOPE.equals(authorityStrategy)) {
            throw new IllegalStateException("SCOPE authority strategy not supported for MVC apps");
        }
    }
    
    public Map<String, Object> getUserMetadata() {
        return userMetadata;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getUserId() {
        return userId;
    }

    public String getNickname() {
        return nickname;
    }

    public String getPicture() {
        return picture;
    }

    public List<UserIdentity> getIdentities() {
        return identities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * Will return UnsupportedOperationException
     */
    @Override
    public String getPassword() {
        throw null;
    }

    /**
     * Gets the email if it exists otherwise it returns the user_id
     */
    @Override
    public String getUsername() {
        return username;
    }

    /**
     * Indicates whether the user's account has expired. An expired account cannot be
     * authenticated.
     *
     * @return <code>true</code> if the user's account is valid (ie non-expired),
     * <code>false</code> if no longer valid (ie expired)
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is locked or unlocked. A locked user cannot be
     * authenticated.
     *
     * @return <code>true</code> if the user is not locked, <code>false</code> otherwise
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Indicates whether the user's credentials (password) has expired. Expired
     * credentials prevent authentication.
     *
     * @return <code>true</code> if the user's credentials are valid (ie non-expired),
     * <code>false</code> if no longer valid (ie expired)
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Will return true if the email is verified, otherwise it will return false
     */
    @Override
    public boolean isEnabled() {
        return emailVerified;
    }


}
