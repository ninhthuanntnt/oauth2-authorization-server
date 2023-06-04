package com.ntnt.microservices.oauth2.authorization.server.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "registered_clients")
public class RegisteredClientDomain {
  @Id
  @Column(name = "id", nullable = false)
  private String id;

  @Column(name = "client_id", nullable = false)
  private String clientId;

  @Column(name = "client_id_issued_at", nullable = false)
  private Instant clientIdIssuedAt = Instant.now();

  @Column(name = "client_secret")
  private String clientSecret;

  @Column(name = "client_secret_expires_at")
  private Instant clientSecretExpiresAt;

  @Column(name = "client_name", nullable = false)
  private String clientName;

  @Column(name = "client_authentication_methods", nullable = false, length = 1000)
  private String clientAuthenticationMethods;

  @Column(name = "authorization_grant_types", nullable = false, length = 1000)
  private String authorizationGrantTypes;

  @Column(name = "redirect_uris", length = 1000)
  private String redirectUris;

  @Column(name = "post_logout_redirect_uris", length = 1000)
  private String postLogoutRedirectUris;

  @Column(name = "scopes", nullable = false, length = 1000)
  private String scopes;

  @Column(name = "client_settings", nullable = false, length = 2000)
  private String clientSettings;

  @Column(name = "token_settings", nullable = false, length = 2000)
  private String tokenSettings;
}
