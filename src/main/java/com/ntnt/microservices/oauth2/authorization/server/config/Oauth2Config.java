package com.ntnt.microservices.oauth2.authorization.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class Oauth2Config {
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(Customizer.withDefaults());  // Enable OpenID Connect 1.0
    http
        // Redirect to the login page when not authenticated from the
        // authorization endpoint

        .exceptionHandling(
            exceptionHandling ->
                exceptionHandling
                    .defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/login"),
                                                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
        // Accept access tokens for User Info and/or Client Registration
        .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));

    return http.build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                                  .clientId("ntnt-oidc-client")
                                                  .clientSecret("{noop}ntnt-secret")
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

    return new InMemoryRegisteredClientRepository(oidcClient, publicClient);
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }
}
