package com.ntnt.microservices.oauth2.authorization.server.security;

import lombok.Getter;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.List;

@Getter
public class CustomUserDetails implements UserDetails, CredentialsContainer {
  private final Long id;

  private final String username;

  private String password;

  private final List<GrantedAuthority> authorities;

  private final boolean accountNonExpired;

  private final boolean accountNonLocked;

  private final boolean credentialsNonExpired;

  private final boolean enabled;

  private final boolean enabledMfa;

  public CustomUserDetails(Long id,
                           String username,
                           String password,
                           List<GrantedAuthority> authorities,
                           boolean accountNonExpired,
                           boolean accountNonLocked,
                           boolean credentialsNonExpired,
                           boolean enabled,
                           boolean enabledMfa) {
    this.id = id;
    this.username = username;
    this.password = password;
    this.authorities = authorities;
    this.accountNonExpired = accountNonExpired;
    this.accountNonLocked = accountNonLocked;
    this.credentialsNonExpired = credentialsNonExpired;
    this.enabled = enabled;
    this.enabledMfa = enabledMfa;
  }

  public CustomUserDetails(Long id,
                           String username,
                           String password,
                           List<? extends GrantedAuthority> authorities,
                           boolean enabledMfa) {
    this(id, username, password, Collections.unmodifiableList(authorities),
         true, true, true, true, enabledMfa);
  }

  public CustomUserDetails(Long id,
                           String username,
                           String password,
                           List<? extends GrantedAuthority> authorities) {
    this(id, username, password, Collections.unmodifiableList(authorities),
         true, true, true, true, false);
  }

  @Override
  public void eraseCredentials() {
    this.password = null;
  }
}
