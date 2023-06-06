package com.ntnt.microservices.oauth2.authorization.server.util;


import com.ntnt.microservices.oauth2.authorization.server.security.CustomUserDetails;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.Principal;

public final class SecurityUtil {

  public static Long getCurrentUserId() {
    CustomUserDetails customUserDetails = (CustomUserDetails) SecurityContextHolder.getContext()
                                                                                   .getAuthentication()
                                                                                   .getPrincipal();

    return customUserDetails.getId();
  }

  public static Object getCurrentPrincipal() {
    return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
  }
}
