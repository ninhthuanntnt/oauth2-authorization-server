package com.ntnt.microservices.oauth2.authorization.server.seeder;

import com.ntnt.microservices.oauth2.authorization.server.security.repository.JpaRegisteredClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

@RequiredArgsConstructor
@Component
public class RegisteredClientSeeder implements CommandLineRunner {
  private final JpaRegisteredClientRepository registeredClientRepository;
  private final PasswordEncoder passwordEncoder;

  @Override
  public void run(String... args) throws Exception {
    RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                                  .clientId("ntnt-oidc-client")
                                                  .clientSecret(passwordEncoder.encode("ntnt-secret"))
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

    registeredClientRepository.save(oidcClient);
    registeredClientRepository.save(publicClient);
  }
}
