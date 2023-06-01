package com.ntnt.microservices.oauth2.authorization.server.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Objects;

public class MfaAuthenticationProvider implements AuthenticationProvider {
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    MfaAuthenticationToken mfaAuthenticationToken = (MfaAuthenticationToken) authentication;
    if (Objects.equals(mfaAuthenticationToken.getCode(), "123456")) {
      return mfaAuthenticationToken.getDelegateAuthentication();
    }
    return null;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return MfaAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
