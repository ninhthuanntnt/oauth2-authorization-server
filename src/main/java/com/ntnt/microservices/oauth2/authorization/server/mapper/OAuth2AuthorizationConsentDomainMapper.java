package com.ntnt.microservices.oauth2.authorization.server.mapper;

import com.ntnt.microservices.oauth2.authorization.server.domain.OAuth2AuthorizationConsentDomain;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Set;

@Component
public class OAuth2AuthorizationConsentDomainMapper {

  public OAuth2AuthorizationConsent toObject(OAuth2AuthorizationConsentDomain authorizationConsentDomain,
                                             RegisteredClient registeredClient) {
    OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(
        registeredClient.getId(), authorizationConsentDomain.getPrincipalName());
    if (authorizationConsentDomain.getAuthorities() != null) {
      for (String authority : StringUtils.commaDelimitedListToSet(authorizationConsentDomain.getAuthorities())) {
        builder.authority(new SimpleGrantedAuthority(authority));
      }
    }

    return builder.build();
  }

  public OAuth2AuthorizationConsentDomain toEntity(OAuth2AuthorizationConsent authorizationConsent) {
    OAuth2AuthorizationConsentDomain entity = new OAuth2AuthorizationConsentDomain();
    entity.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
    entity.setPrincipalName(authorizationConsent.getPrincipalName());

    Set<String> authorities = new HashSet<>();
    for (GrantedAuthority authority : authorizationConsent.getAuthorities()) {
      authorities.add(authority.getAuthority());
    }
    entity.setAuthorities(StringUtils.collectionToCommaDelimitedString(authorities));

    return entity;
  }
}
