package com.ntnt.microservices.oauth2.authorization.server.util;


import com.ntnt.microservices.oauth2.authorization.server.security.CustomUserDetails;
import org.springframework.security.core.context.SecurityContextHolder;

public final class SecurityUtil {

  public static Long getCurrentUserId() {
    CustomUserDetails customUserDetails = (CustomUserDetails) SecurityContextHolder.getContext()
                                                                                   .getAuthentication()
                                                                                   .getPrincipal();

    return customUserDetails.getId();
  }
}
