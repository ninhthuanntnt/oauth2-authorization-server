package com.ntnt.microservices.oauth2.authorization.server.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class EventHandler {
  @EventListener(AuthenticationSuccessEvent.class)
  public void handleAuthenticationSuccessEvent(AuthenticationSuccessEvent event) {
    log.info("NTNT-AuthenticationSuccessEvent-Authentication: {}", event.getAuthentication());
    log.info("NTNT-AuthenticationSuccessEvent-Authentication-Principal: {}", event.getAuthentication().getPrincipal());
  }
}
