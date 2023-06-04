package com.ntnt.microservices.oauth2.authorization.server.repository;

import com.ntnt.microservices.oauth2.authorization.server.domain.UserRoleDomain;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRoleDomainRepository extends JpaRepository<UserRoleDomain, UserRoleDomain.UserRoleDomainId> {
}
