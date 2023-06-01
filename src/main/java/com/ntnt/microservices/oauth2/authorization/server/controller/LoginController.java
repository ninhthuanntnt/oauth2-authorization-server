package com.ntnt.microservices.oauth2.authorization.server.controller;

import com.ntnt.microservices.oauth2.authorization.server.config.DefaultSecurityConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class LoginController {

  private final AuthenticationManager authenticationManager;
  @GetMapping("/login")
  public String login() {
    return "login";
  }

  @GetMapping(DefaultSecurityConfig.MFA_URL)
  public String login2fa() {
    return "2fa";
  }
}
