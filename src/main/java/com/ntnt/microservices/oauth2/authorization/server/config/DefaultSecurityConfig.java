package com.ntnt.microservices.oauth2.authorization.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
    return httpSecurity
        .authorizeHttpRequests(
            authorizeRequests ->
                authorizeRequests.requestMatchers("/assets/**", "/static/**", "/webjars/**", "/login").permitAll()
                                 .anyRequest().authenticated())
        .formLogin(formLogin -> formLogin.loginPage("/login"))
        .build();
  }
}
