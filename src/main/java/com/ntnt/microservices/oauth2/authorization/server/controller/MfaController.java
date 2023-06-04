package com.ntnt.microservices.oauth2.authorization.server.controller;

import com.ntnt.microservices.oauth2.authorization.server.config.DefaultSecurityConfig;
import com.ntnt.microservices.oauth2.authorization.server.service.UserDomainService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RequiredArgsConstructor
@Controller
@RequestMapping(DefaultSecurityConfig.MFA_URL)
public class MfaController {
  private final UserDomainService userDomainService;
  @GetMapping
  public String loginMfa() {
    return "mfa";
  }

  @PostMapping("/setup")
  public String enableMfa(@RequestParam(required = false) boolean enabledMfa, Model model) {
    String qrCode = userDomainService.setupMfa(enabledMfa);
    model.addAttribute("qrCode", qrCode);

     if(enabledMfa) {
      return "mfa-qr-code";
    } else {
      return "redirect:/setting";
    }
  }
}
