package com.ntnt.microservices.oauth2.authorization.server.config;

import dev.samstevens.totp.spring.autoconfigure.TotpAutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.context.annotation.Configuration;

@Configuration
@ImportAutoConfiguration(TotpAutoConfiguration.class)
public class TotpConfig {
}