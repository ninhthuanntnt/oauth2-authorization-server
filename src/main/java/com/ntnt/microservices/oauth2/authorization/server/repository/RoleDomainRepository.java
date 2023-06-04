package com.ntnt.microservices.oauth2.authorization.server.repository;

import com.ntnt.microservices.oauth2.authorization.server.domain.RoleDomain;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleDomainRepository extends JpaRepository<RoleDomain, Long> {
}
