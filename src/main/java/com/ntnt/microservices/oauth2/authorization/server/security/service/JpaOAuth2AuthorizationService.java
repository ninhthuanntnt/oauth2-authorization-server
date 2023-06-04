package com.ntnt.microservices.oauth2.authorization.server.security.service;

import com.ntnt.microservices.oauth2.authorization.server.domain.OAuth2AuthorizationDomain;
import com.ntnt.microservices.oauth2.authorization.server.mapper.OAuth2AuthorizationDomainMapper;
import com.ntnt.microservices.oauth2.authorization.server.repository.OAuth2AuthorizationDomainRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {
  private final OAuth2AuthorizationDomainRepository oAuth2AuthorizationRepository;
  private final RegisteredClientRepository registeredClientRepository;
  private final OAuth2AuthorizationDomainMapper oAuth2AuthorizationMapper;

  @Override
  public void save(OAuth2Authorization authorization) {
    Assert.notNull(authorization, "authorization cannot be null");
    this.oAuth2AuthorizationRepository.save(oAuth2AuthorizationMapper.toEntity(authorization));
  }

  @Override
  public void remove(OAuth2Authorization authorization) {
    Assert.notNull(authorization, "authorization cannot be null");
    this.oAuth2AuthorizationRepository.deleteById(authorization.getId());
  }

  @Override
  public OAuth2Authorization findById(String id) {
    Assert.hasText(id, "id cannot be empty");
    OAuth2AuthorizationDomain oAuth2AuthorizationDomain = this.oAuth2AuthorizationRepository.findById(id)
                                                                                            .orElse(null);

    Assert.notNull(oAuth2AuthorizationDomain, "oAuth2AuthorizationDomain cannot be null");
    RegisteredClient registeredClient = this.registeredClientRepository.findById(oAuth2AuthorizationDomain.getRegisteredClientId());

    return oAuth2AuthorizationMapper.toObject(oAuth2AuthorizationDomain, registeredClient);
  }

  @Override
  public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
    Assert.hasText(token, "token cannot be empty");

    Optional<OAuth2AuthorizationDomain> result;
    if (tokenType == null) {
      result = this.oAuth2AuthorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(token);
    } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
      result = this.oAuth2AuthorizationRepository.findByState(token);
    } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
      result = this.oAuth2AuthorizationRepository.findByAuthorizationCodeValue(token);
    } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
      result = this.oAuth2AuthorizationRepository.findByAccessTokenValue(token);
    } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
      result = this.oAuth2AuthorizationRepository.findByRefreshTokenValue(token);
    } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
      result = this.oAuth2AuthorizationRepository.findByOidcIdTokenValue(token);
    } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
      result = this.oAuth2AuthorizationRepository.findByUserCodeValue(token);
    } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
      result = this.oAuth2AuthorizationRepository.findByDeviceCodeValue(token);
    } else {
      result = Optional.empty();
    }

    return result.map(oAuth2AuthorizationDomain -> {
      RegisteredClient registeredClient = this.registeredClientRepository.findById(oAuth2AuthorizationDomain.getRegisteredClientId());
      return oAuth2AuthorizationMapper.toObject(oAuth2AuthorizationDomain, registeredClient);
    }).orElse(null);
  }
}
