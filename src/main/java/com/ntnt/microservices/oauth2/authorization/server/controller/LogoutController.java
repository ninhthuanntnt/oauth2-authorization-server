package com.ntnt.microservices.oauth2.authorization.server.controller;

import com.ntnt.microservices.oauth2.authorization.server.util.SecurityUtil;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Objects;

@RequiredArgsConstructor
@Controller
public class LogoutController {

  private final SessionRegistry sessionRegistry;

  @GetMapping("/logout-all")
  public String logoutAll(HttpSession session) {
    sessionRegistry.getAllSessions(SecurityUtil.getCurrentPrincipal(), false)
                   .stream()
                   .filter(sessionInformation -> !Objects.equals(sessionInformation.getSessionId(), session.getId()))
                   .forEach(SessionInformation::expireNow);

    return "redirect:/logout";
  }
}
