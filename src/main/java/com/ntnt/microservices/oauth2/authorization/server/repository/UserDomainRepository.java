package com.ntnt.microservices.oauth2.authorization.server.repository;

import com.ntnt.microservices.oauth2.authorization.server.domain.UserDomain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserDomainRepository extends JpaRepository<UserDomain, Long> {

  @Query("""
         SELECT u
         FROM UserDomain u
         LEFT JOIN FETCH u.userRoles ur
         LEFT JOIN FETCH ur.role r
         WHERE u.username = :username
         """)
  Optional<UserDomain> findByUsername(String username);
}
