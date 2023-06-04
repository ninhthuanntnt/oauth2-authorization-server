package com.ntnt.microservices.oauth2.authorization.server.controller;

import com.ntnt.microservices.oauth2.authorization.server.service.UserDomainService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@RequiredArgsConstructor
@Controller
@RequestMapping("/setting")
public class SettingController {

  private final UserDomainService userDomainService;

  @GetMapping
  public String setting(Model model) {
    model.addAttribute("user", userDomainService.getCurrentUser());
    return "setting";
  }
}
