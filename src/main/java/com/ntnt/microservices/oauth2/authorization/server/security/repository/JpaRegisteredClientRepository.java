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
