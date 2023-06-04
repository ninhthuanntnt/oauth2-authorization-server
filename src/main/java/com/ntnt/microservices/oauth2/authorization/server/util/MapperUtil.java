package com.ntnt.microservices.oauth2.authorization.server.util;

import com.fasterxml.jackson.databind.ObjectMapper;

public final class MapperUtil {
  public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  public static <T> T map(Object source, Class<T> targetClass) {
    return null;
  }
}
