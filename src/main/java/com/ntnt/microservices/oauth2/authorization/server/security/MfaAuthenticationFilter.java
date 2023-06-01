package com.ntnt.microservices.oauth2.authorization.server.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

public class MfaAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
  public MfaAuthenticationFilter(AntPathRequestMatcher antPathRequestMatcher,
                                 AuthenticationManager authenticationManager) {
    super(antPathRequestMatcher, authenticationManager);
  }

  protected MfaAuthenticationFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
    super(defaultFilterProcessesUrl, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
    String code = request.getParameter("code");
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    if(authentication instanceof MfaAuthenticationToken) {
      return this.getAuthenticationManager()
                 .authenticate(new MfaAuthenticationToken(((MfaAuthenticationToken) authentication).getDelegateAuthentication(), code));
    }

    return null;
  }
}
