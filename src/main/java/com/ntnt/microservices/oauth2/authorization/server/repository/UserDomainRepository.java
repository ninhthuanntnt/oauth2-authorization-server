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
         WHERE u.username = :value OR u.email = :value
         """)
  Optional<UserDomain> getByUsernameOrEmail(String value);

  boolean existsByUsername(String username);

  boolean existsByEmail(String email);

  Optional<UserDomain> findByEmail(String email);
}
