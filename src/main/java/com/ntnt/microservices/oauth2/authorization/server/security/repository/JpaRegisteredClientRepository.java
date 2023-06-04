package com.ntnt.microservices.oauth2.authorization.server.security.repository;

import com.ntnt.microservices.oauth2.authorization.server.mapper.RegisteredClientDomainMapper;
import com.ntnt.microservices.oauth2.authorization.server.repository.RegisteredClientDomainRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.UUID;

@RequiredArgsConstructor
@Component("registeredClientRepository")
public class JpaRegisteredClientRepository implements RegisteredClientRepository {
  private final RegisteredClientDomainRepository registeredClientRepository;
  private final RegisteredClientDomainMapper registeredClientDomainMapper;

  @PostConstruct
  public void init() {
    RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                                  .clientId("ntnt-oidc-client")
                                                  .clientSecret("{noop}ntnt-secret")
                                                  .clientIdIssuedAt(Instant.now())
                                                  .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                                  .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                                                  .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                                  .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                                  .redirectUri("https://oauth.pstmn.io/v1/callback")
                                                  .postLogoutRedirectUri("http://127.0.0.1:8080")
                                                  .scope(OidcScopes.OPENID)
                                                  .scope(OidcScopes.PROFILE)
                                                  .tokenSettings(TokenSettings.builder().build())
                                                  .clientSettings(ClientSettings.builder()
                                                                                .requireAuthorizationConsent(true)
                                                                                .build())
                                                  .build();

    RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                                    .clientId("ntnt-public-oidc-client")
                                                    .clientIdIssuedAt(Instant.now())
                                                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                                                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                                    .redirectUri("https://oauth.pstmn.io/v1/callback")
                                                    .postLogoutRedirectUri("http://127.0.0.1:8080")
                                                    .scope(OidcScopes.OPENID)
                                                    .scope(OidcScopes.PROFILE)
                                                    .tokenSettings(TokenSettings.builder().build())
                                                    .clientSettings(ClientSettings.builder()
                                                                                  .requireProofKey(true)
                                                                                  .requireAuthorizationConsent(true)
                                                                                  .build())
                                                    .build();

    save(oidcClient);
    save(publicClient);
  }

  @Override
  public void save(RegisteredClient registeredClient) {
    Assert.notNull(registeredClient, "registeredClient cannot be null");
    this.registeredClientRepository.save(registeredClientDomainMapper.toEntity(registeredClient));
  }

  @Override
  public RegisteredClient findById(String id) {
    Assert.hasText(id, "id cannot be empty");
    return this.registeredClientRepository.findById(id).map(registeredClientDomainMapper::toObject).orElse(null);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    Assert.hasText(clientId, "clientId cannot be empty");
    return this.registeredClientRepository.findByClientId(clientId).map(registeredClientDomainMapper::toObject).orElse(null);
  }
}
