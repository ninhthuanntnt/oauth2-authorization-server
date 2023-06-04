package com.ntnt.microservices.oauth2.authorization.server.repository;

import com.ntnt.microservices.oauth2.authorization.server.domain.OAuth2AuthorizationDomain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface OAuth2AuthorizationDomainRepository extends JpaRepository<OAuth2AuthorizationDomain, String> {
  Optional<OAuth2AuthorizationDomain> findByState(String state);

  Optional<OAuth2AuthorizationDomain> findByAuthorizationCodeValue(String authorizationCode);

  Optional<OAuth2AuthorizationDomain> findByAccessTokenValue(String accessToken);

  Optional<OAuth2AuthorizationDomain> findByRefreshTokenValue(String refreshToken);

  Optional<OAuth2AuthorizationDomain> findByOidcIdTokenValue(String idToken);

  Optional<OAuth2AuthorizationDomain> findByUserCodeValue(String userCode);

  Optional<OAuth2AuthorizationDomain> findByDeviceCodeValue(String deviceCode);

  @Query("""
         SELECT a FROM OAuth2AuthorizationDomain a
         WHERE a.state = :token
           OR a.authorizationCodeValue = :token
           OR a.accessTokenValue = :token
           OR a.refreshTokenValue = :token
           OR a.oidcIdTokenValue = :token
           OR a.userCodeValue = :token
           OR a.deviceCodeValue = :token
         """)
  Optional<OAuth2AuthorizationDomain> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(@Param("token") String token);
}