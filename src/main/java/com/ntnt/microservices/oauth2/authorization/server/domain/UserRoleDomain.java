package com.ntnt.microservices.oauth2.authorization.server.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Objects;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "user_roles")
@IdClass(UserRoleDomain.UserRoleDomainId.class)
public class UserRoleDomain {
  @Id
  @Column(name = "user_id", nullable = false)
  private Long userId;

  @Id
  @Column(name = "role_id", nullable = false)
  private Long roleId;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id", insertable = false, updatable = false)
  private UserDomain user;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "role_id", insertable = false, updatable = false)
  private RoleDomain role;

  public static class UserRoleDomainId {
    private Long userId;
    private Long roleId;

    @Override
    public boolean equals(Object o) {
      if (this==o) return true;
      if (o==null || getClass()!=o.getClass()) return false;
      UserRoleDomainId that = (UserRoleDomainId) o;
      return userId.equals(that.userId) && roleId.equals(that.roleId);
    }

    @Override
    public int hashCode() {
      return Objects.hash(userId, roleId);
    }
  }
}
