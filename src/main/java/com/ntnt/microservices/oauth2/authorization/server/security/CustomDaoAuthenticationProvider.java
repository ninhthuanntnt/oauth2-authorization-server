package com.ntnt.microservices.oauth2.authorization.server.security;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

public class CustomDaoAuthenticationProvider extends DaoAuthenticationProvider {
  public CustomDaoAuthenticationProvider() {
    super();
  }

  @Override
  protected Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {

    Authentication successAuthentication = super.createSuccessAuthentication(principal, authentication, user);
    boolean enabled2FA = successAuthentication.getAuthorities()
                                              .stream()
                                              .anyMatch(grantedAuthority -> grantedAuthority.getAuthority()
                                                                                            .equals("ROLE_2FA"));

    if (enabled2FA) {
      return new MfaAuthenticationToken(successAuthentication, null);
    }

    return successAuthentication;
  }
}
