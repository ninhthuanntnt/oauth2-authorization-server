package com.ntnt.microservices.oauth2.authorization.server.security.service;

import com.ntnt.microservices.oauth2.authorization.server.mapper.OAuth2AuthorizationConsentDomainMapper;
import com.ntnt.microservices.oauth2.authorization.server.repository.OAuth2AuthorizationConsentDomainRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

@RequiredArgsConstructor
@Service
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {
  private final OAuth2AuthorizationConsentDomainRepository authorizationConsentRepository;
  private final RegisteredClientRepository registeredClientRepository;
  private final OAuth2AuthorizationConsentDomainMapper authorizationConsentMapper;

  @Override
  public void save(OAuth2AuthorizationConsent authorizationConsent) {
    Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
    this.authorizationConsentRepository.save(authorizationConsentMapper.toEntity(authorizationConsent));
  }

  @Override
  public void remove(OAuth2AuthorizationConsent authorizationConsent) {
    Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
    this.authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
        authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
  }

  @Override
  public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
    Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
    Assert.hasText(principalName, "principalName cannot be empty");
    return
        this.authorizationConsentRepository
            .findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName)
            .map(authorizationConsentDomain -> {
              RegisteredClient registeredClient = this.registeredClientRepository.findById(registeredClientId);
              if (registeredClient==null) {
                throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + registeredClientId + "' was not found in the RegisteredClientRepository.");
              }
              return authorizationConsentMapper.toObject(authorizationConsentDomain, registeredClient);
            })
            .orElse(null);

  }

}