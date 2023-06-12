package com.ntnt.microservices.oauth2.authorization.server.domain;


import com.ntnt.microservices.oauth2.authorization.server.domain.constant.IdentityProvider;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "users")
public class UserDomain {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "username", nullable = false, unique = true)
  private String username;

  @Column(name = "password", nullable = false)
  private String password;

  @Column(name = "email", unique = true)
  private String email;

  @Builder.Default
  @Column(name = "identity_provider", nullable = false)
  private IdentityProvider identityProvider = IdentityProvider.LOCAL;

  @Column(name = "enabled_mfa", nullable = false)
  private boolean enabledMfa;

  @Column(name = "mfa_secret")
  private String mfaSecret;

  @Column(name = "mfa_recovery_code")
  private String mfaRecoveryCode;

  @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
  private List<UserRoleDomain> userRoles;
}
