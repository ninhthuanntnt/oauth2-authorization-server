package com.ntnt.microservices.oauth2.authorization.server.repository;

import com.ntnt.microservices.oauth2.authorization.server.domain.RegisteredClientDomain;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RegisteredClientDomainRepository extends JpaRepository<RegisteredClientDomain, String> {
  Optional<RegisteredClientDomain> findByClientId(String clientId);
}
