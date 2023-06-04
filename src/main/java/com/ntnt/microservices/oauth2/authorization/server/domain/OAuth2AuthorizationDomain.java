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
@Table(name = "oauth2_authorizations")
public class OAuth2AuthorizationDomain {

  @Id
  @Column(name = "id", nullable = false)
  private String id;

  @Column(name = "registered_client_id", nullable = false)
  private String registeredClientId;

  @Column(name = "principal_name", nullable = false)
  private String principalName;

  @Column(name = "authorization_grant_type", nullable = false)
  private String authorizationGrantType;

  @Column(name = "authorized_scopes")
  private String authorizedScopes;

  @Column(name = "attributes")
  private String attributes;

  @Column(name = "state")
  private String state;

  @Column(name = "authorization_code_value")
  private String authorizationCodeValue;

  @Column(name = "authorization_code_issued_at")
  private Instant authorizationCodeIssuedAt;

  @Column(name = "authorization_code_expires_at")
  private Instant authorizationCodeExpiresAt;

  @Column(name = "authorization_code_metadata")
  private String authorizationCodeMetadata;

  @Column(name = "access_token_value")
  private String accessTokenValue;

  @Column(name = "access_token_issued_at")
  private Instant accessTokenIssuedAt;

  @Column(name = "access_token_expires_at")
  private Instant accessTokenExpiresAt;

  @Column(name = "access_token_metadata")
  private String accessTokenMetadata;

  @Column(name = "access_token_type")
  private String accessTokenType;

  @Column(name = "access_token_scopes")
  private String accessTokenScopes;

  @Column(name = "refresh_token_value")
  private String refreshTokenValue;

  @Column(name = "refresh_token_issued_at")
  private Instant refreshTokenIssuedAt;

  @Column(name = "refresh_token_expires_at")
  private Instant refreshTokenExpiresAt;

  @Column(name = "refresh_token_metadata")
  private String refreshTokenMetadata;

  @Column(name = "oidc_id_token_value")
  private String oidcIdTokenValue;

  @Column(name = "oidc_id_token_issued_at")
  private Instant oidcIdTokenIssuedAt;

  @Column(name = "oidc_id_token_expires_at")
  private Instant oidcIdTokenExpiresAt;

  @Column(name = "oidc_id_token_metadata")
  private String oidcIdTokenMetadata;

  @Column(name = "oidc_id_token_claims")
  private String oidcIdTokenClaims;

  @Column(name = "user_code_value")
  private String userCodeValue;

  @Column(name = "user_code_issued_at")
  private Instant userCodeIssuedAt;

  @Column(name = "user_code_expires_at")
  private Instant userCodeExpiresAt;

  @Column(name = "user_code_metadata")
  private String userCodeMetadata;

  @Column(name = "device_code_value")
  private String deviceCodeValue;

  @Column(name = "device_code_issued_at")
  private Instant deviceCodeIssuedAt;

  @Column(name = "device_code_expires_at")
  private Instant deviceCodeExpiresAt;

  @Column(name = "device_code_metadata")
  private String deviceCodeMetadata;

}
