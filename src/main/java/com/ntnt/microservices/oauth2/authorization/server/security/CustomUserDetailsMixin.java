package com.ntnt.microservices.oauth2.authorization.server.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

public abstract class CustomUserDetailsMixin {
  @JsonCreator
  CustomUserDetailsMixin(@JsonProperty("id") Long id,
                         @JsonProperty("username") String username,
                         @JsonProperty("password") String password,
                         @JsonProperty("authorities") List<GrantedAuthority> authorities,
                         @JsonProperty("accountNonExpired") boolean accountNonExpired,
                         @JsonProperty("accountNonLocked") boolean accountNonLocked,
                         @JsonProperty("credentialsNonExpired") boolean credentialsNonExpired,
                         @JsonProperty("enabled") boolean enabled,
                         @JsonProperty("enabledMfa") boolean enabledMfa) {
  }
}