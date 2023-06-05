package com.ntnt.microservices.oauth2.authorization.server.mapper;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ntnt.microservices.oauth2.authorization.server.domain.OAuth2AuthorizationDomain;
import com.ntnt.microservices.oauth2.authorization.server.security.CustomUserDetails;
import com.ntnt.microservices.oauth2.authorization.server.security.CustomUserDetailsMixin;
import com.ntnt.microservices.oauth2.authorization.server.security.repository.JpaRegisteredClientRepository;
import com.ntnt.microservices.oauth2.authorization.server.security.service.JpaOAuth2AuthorizationService;
import org.apache.catalina.mbeans.SparseUserDatabaseMBean;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

@Component
public class OAuth2AuthorizationDomainMapper {
  private final ObjectMapper objectMapper;

  public OAuth2AuthorizationDomainMapper() {
    this.objectMapper = new ObjectMapper();
    ClassLoader classLoader = JpaOAuth2AuthorizationService.class.getClassLoader();
    List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
    this.objectMapper.registerModules(securityModules);
    this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    this.objectMapper.registerModule(new CoreJackson2Module());
    this.objectMapper.addMixIn(CustomUserDetails.class, CustomUserDetailsMixin.class);
  }

  public static void main(String[] args) {
    String value = """
                   {"@class":"java.util.Collections$UnmodifiableMap","java.security.Principal":{"@class":"org.springframework.security.authentication.UsernamePasswordAuthenticationToken","authorities":["java.util.Collections$UnmodifiableRandomAccessList",[{"@class":"org.springframework.security.core.authority.SimpleGrantedAuthority","authority":"ROLE_USER"}]],"details":{"@class":"org.springframework.security.web.authentication.WebAuthenticationDetails","remoteAddress":"127.0.0.1","sessionId":"30ED71D6054952C13A4F938AF5496C17"},"authenticated":true,"principal":{"@class":"com.ntnt.microservices.oauth2.authorization.server.security.CustomUserDetails","id":1,"username":"user1","password":null,"authorities":["java.util.Collections$UnmodifiableRandomAccessList",[{"@class":"org.springframework.security.core.authority.SimpleGrantedAuthority","authority":"ROLE_USER"}]],"accountNonExpired":true,"accountNonLocked":true,"credentialsNonExpired":true,"enabled":true,"enabledMfa":false},"credentials":null},"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest":{"@class":"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest","authorizationUri":"http://127.0.0.1:8080/oauth2/authorize","authorizationGrantType":{"value":"authorization_code"},"responseType":{"value":"code"},"clientId":"ntnt-oidc-client","redirectUri":"https://oauth.pstmn.io/v1/callback","scopes":["java.util.Collections$UnmodifiableSet",["openid","profile"]],"state":"oilas987123hjljhdifs","additionalParameters":{"@class":"java.util.Collections$UnmodifiableMap","continue":""},"authorizationRequestUri":"http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=ntnt-oidc-client&scope=openid%20profile&state=oilas987123hjljhdifs&redirect_uri=https://oauth.pstmn.io/v1/callback&continue=","attributes":{"@class":"java.util.Collections$UnmodifiableMap"}},"state":"Jubjrp7TZx-QThjTpPdUkcyNi416F6fUWYjEgJGRJGA="}
                   """;
    OAuth2AuthorizationDomainMapper mapper = new OAuth2AuthorizationDomainMapper();

    System.out.println(mapper.parseMap(value));
  }

  public OAuth2Authorization toObject(OAuth2AuthorizationDomain entity, RegisteredClient registeredClient) {
    if (registeredClient == null) {
      throw new DataRetrievalFailureException(
          "The RegisteredClient with id '" + entity.getRegisteredClientId() + "' was not found in the RegisteredClientRepository.");
    }

    OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                                                             .id(entity.getId())
                                                             .principalName(entity.getPrincipalName())
                                                             .authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
                                                             .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()))
                                                             .attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())));
    if (entity.getState() != null) {
      builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
    }

    if (entity.getAuthorizationCodeValue() != null) {
      OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
          entity.getAuthorizationCodeValue(),
          entity.getAuthorizationCodeIssuedAt(),
          entity.getAuthorizationCodeExpiresAt());
      builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(entity.getAuthorizationCodeMetadata())));
    }

    if (entity.getAccessTokenValue() != null) {
      OAuth2AccessToken accessToken = new OAuth2AccessToken(
          OAuth2AccessToken.TokenType.BEARER,
          entity.getAccessTokenValue(),
          entity.getAccessTokenIssuedAt(),
          entity.getAccessTokenExpiresAt(),
          StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes()));
      builder.token(accessToken, metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())));
    }

    if (entity.getRefreshTokenValue() != null) {
      OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
          entity.getRefreshTokenValue(),
          entity.getRefreshTokenIssuedAt(),
          entity.getRefreshTokenExpiresAt());
      builder.token(refreshToken, metadata -> metadata.putAll(parseMap(entity.getRefreshTokenMetadata())));
    }

    if (entity.getOidcIdTokenValue() != null) {
      OidcIdToken idToken = new OidcIdToken(
          entity.getOidcIdTokenValue(),
          entity.getOidcIdTokenIssuedAt(),
          entity.getOidcIdTokenExpiresAt(),
          parseMap(entity.getOidcIdTokenClaims()));
      builder.token(idToken, metadata -> metadata.putAll(parseMap(entity.getOidcIdTokenMetadata())));
    }

    if (entity.getUserCodeValue() != null) {
      OAuth2UserCode userCode = new OAuth2UserCode(
          entity.getUserCodeValue(),
          entity.getUserCodeIssuedAt(),
          entity.getUserCodeExpiresAt());
      builder.token(userCode, metadata -> metadata.putAll(parseMap(entity.getUserCodeMetadata())));
    }

    if (entity.getDeviceCodeValue() != null) {
      OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
          entity.getDeviceCodeValue(),
          entity.getDeviceCodeIssuedAt(),
          entity.getDeviceCodeExpiresAt());
      builder.token(deviceCode, metadata -> metadata.putAll(parseMap(entity.getDeviceCodeMetadata())));
    }

    return builder.build();
  }

  public OAuth2AuthorizationDomain toEntity(OAuth2Authorization authorization) {
    OAuth2AuthorizationDomain entity = new OAuth2AuthorizationDomain();
    entity.setId(authorization.getId());
    entity.setRegisteredClientId(authorization.getRegisteredClientId());
    entity.setPrincipalName(authorization.getPrincipalName());
    entity.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
    entity.setAuthorizedScopes(StringUtils.collectionToDelimitedString(authorization.getAuthorizedScopes(), ","));
    entity.setAttributes(writeMap(authorization.getAttributes()));
    entity.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));

    OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
        authorization.getToken(OAuth2AuthorizationCode.class);
    setTokenValues(
        authorizationCode,
        entity::setAuthorizationCodeValue,
        entity::setAuthorizationCodeIssuedAt,
        entity::setAuthorizationCodeExpiresAt,
        entity::setAuthorizationCodeMetadata
                  );

    OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
        authorization.getToken(OAuth2AccessToken.class);
    setTokenValues(
        accessToken,
        entity::setAccessTokenValue,
        entity::setAccessTokenIssuedAt,
        entity::setAccessTokenExpiresAt,
        entity::setAccessTokenMetadata
                  );
    if (accessToken != null && accessToken.getToken().getScopes() != null) {
      entity.setAccessTokenScopes(StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ","));
    }

    OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
        authorization.getToken(OAuth2RefreshToken.class);
    setTokenValues(
        refreshToken,
        entity::setRefreshTokenValue,
        entity::setRefreshTokenIssuedAt,
        entity::setRefreshTokenExpiresAt,
        entity::setRefreshTokenMetadata
                  );

    OAuth2Authorization.Token<OidcIdToken> oidcIdToken =
        authorization.getToken(OidcIdToken.class);
    setTokenValues(
        oidcIdToken,
        entity::setOidcIdTokenValue,
        entity::setOidcIdTokenIssuedAt,
        entity::setOidcIdTokenExpiresAt,
        entity::setOidcIdTokenMetadata
                  );
    if (oidcIdToken != null) {
      entity.setOidcIdTokenClaims(writeMap(oidcIdToken.getClaims()));
    }

    OAuth2Authorization.Token<OAuth2UserCode> userCode =
        authorization.getToken(OAuth2UserCode.class);
    setTokenValues(
        userCode,
        entity::setUserCodeValue,
        entity::setUserCodeIssuedAt,
        entity::setUserCodeExpiresAt,
        entity::setUserCodeMetadata
                  );

    OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode =
        authorization.getToken(OAuth2DeviceCode.class);
    setTokenValues(
        deviceCode,
        entity::setDeviceCodeValue,
        entity::setDeviceCodeIssuedAt,
        entity::setDeviceCodeExpiresAt,
        entity::setDeviceCodeMetadata
                  );

    return entity;
  }

  private void setTokenValues(
      OAuth2Authorization.Token<?> token,
      Consumer<String> tokenValueConsumer,
      Consumer<Instant> issuedAtConsumer,
      Consumer<Instant> expiresAtConsumer,
      Consumer<String> metadataConsumer) {
    if (token != null) {
      OAuth2Token oAuth2Token = token.getToken();
      tokenValueConsumer.accept(oAuth2Token.getTokenValue());
      issuedAtConsumer.accept(oAuth2Token.getIssuedAt());
      expiresAtConsumer.accept(oAuth2Token.getExpiresAt());
      metadataConsumer.accept(writeMap(token.getMetadata()));
    }
  }

  private Map<String, Object> parseMap(String data) {
    try {
      return this.objectMapper.readValue(data, new TypeReference<>() {});
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }

  private String writeMap(Map<String, Object> metadata) {
    try {
      return this.objectMapper.writeValueAsString(metadata);
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }

  private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
    if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.AUTHORIZATION_CODE;
    } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.CLIENT_CREDENTIALS;
    } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.REFRESH_TOKEN;
    } else if (AuthorizationGrantType.DEVICE_CODE.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.DEVICE_CODE;
    }
    return new AuthorizationGrantType(authorizationGrantType); // Custom authorization grant type
  }
}
