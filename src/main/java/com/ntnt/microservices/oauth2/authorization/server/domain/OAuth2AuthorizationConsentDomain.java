package com.ntnt.microservices.oauth2.authorization.server.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Objects;

@Getter
@Setter
@Entity
@Table(name = "oauth2_authorization_consents")
@IdClass(OAuth2AuthorizationConsentDomain.AuthorizationConsentId.class)
public class OAuth2AuthorizationConsentDomain {
  @Id
  @Column(name = "registered_client_id", nullable = false)
  private String registeredClientId;

  @Id
  @Column(name = "principal_name", length = 255, nullable = false)
  private String principalName;
  @Column(length = 1000)
  private String authorities;

  public static class AuthorizationConsentId implements Serializable {
    private String registeredClientId;
    private String principalName;

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      AuthorizationConsentId that = (AuthorizationConsentId) o;
      return registeredClientId.equals(that.registeredClientId) && principalName.equals(that.principalName);
    }

    @Override
    public int hashCode() {
      return Objects.hash(registeredClientId, principalName);
    }
  }
}
