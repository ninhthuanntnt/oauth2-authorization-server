package com.ntnt.microservices.oauth2.authorization.server.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;

public class CustomSavedRequestAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
  private String defaultMfaTargetUrl;

  public CustomSavedRequestAuthenticationSuccessHandler(String defaultTargetUrl) {
    this.defaultMfaTargetUrl = defaultTargetUrl;
  }


  @Override
  public void onAuthenticationSuccess(HttpServletRequest request,
                                      HttpServletResponse response,
                                      Authentication authentication) throws ServletException, IOException {
    if (authentication instanceof MfaAuthenticationToken) {
      getRedirectStrategy().sendRedirect(request, response, defaultMfaTargetUrl);
      return;
    }
    super.onAuthenticationSuccess(request, response, authentication);
  }
}
