package com.ntnt.microservices.oauth2.authorization.server.repository;

import com.ntnt.microservices.oauth2.authorization.server.domain.OAuth2AuthorizationConsentDomain;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuth2AuthorizationConsentDomainRepository
    extends JpaRepository<OAuth2AuthorizationConsentDomain, OAuth2AuthorizationConsentDomain.AuthorizationConsentId> {
  Optional<OAuth2AuthorizationConsentDomain> findByRegisteredClientIdAndPrincipalName(String registeredClientId,
                                                                                      String principalName);

  void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}