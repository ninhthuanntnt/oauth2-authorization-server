package com.ntnt.microservices.oauth2.authorization.server.exception;

public class NotFoundException extends RuntimeException{

  public NotFoundException (Class<?> resourceClass) {
    super(resourceClass.getName() + " is not found");
  }
}
