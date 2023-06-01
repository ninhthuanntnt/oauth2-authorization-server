package com.ntnt.microservices.oauth2.authorization.server.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;

public class MfaAuthenticationToken extends AbstractAuthenticationToken {
  private Authentication delegateAuthentication;
  private String code;

  public MfaAuthenticationToken(Authentication authentication, String code) {
    super(authentication.getAuthorities());
    this.delegateAuthentication = authentication;
    this.code = code;
  }

  public MfaAuthenticationToken(Authentication authentication) {
    super(authentication.getAuthorities());
    this.delegateAuthentication = authentication;
    this.code = null;
  }

  @Override
  public Object getCredentials() {
    return this.delegateAuthentication.getCredentials();
  }

  @Override
  public Object getPrincipal() {
    return this.delegateAuthentication.getPrincipal();
  }

  @Override
  public void eraseCredentials() {
    if (this.delegateAuthentication instanceof CredentialsContainer) {
      ((CredentialsContainer) this.delegateAuthentication).eraseCredentials();
    }
  }

  @Override
  public boolean isAuthenticated() {
    return false;
  }

  public Authentication getDelegateAuthentication() {
    return this.delegateAuthentication;
  }

  public String getCode() {
    return this.code;
  }
}
