package com.ntnt.microservices.oauth2.authorization.server.seeder;

import com.ntnt.microservices.oauth2.authorization.server.domain.RoleDomain;
import com.ntnt.microservices.oauth2.authorization.server.domain.UserDomain;
import com.ntnt.microservices.oauth2.authorization.server.domain.UserRoleDomain;
import com.ntnt.microservices.oauth2.authorization.server.repository.RoleDomainRepository;
import com.ntnt.microservices.oauth2.authorization.server.repository.UserDomainRepository;
import com.ntnt.microservices.oauth2.authorization.server.repository.UserRoleDomainRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;

@RequiredArgsConstructor
@Component
public class UserAndRoleSeeder implements CommandLineRunner {
  private final UserDomainRepository userDomainRepository;
  private final UserRoleDomainRepository userRoleDomainRepository;
  private final RoleDomainRepository roleDomainRepository;

  @Override
  public void run(String... args) throws Exception {
    RoleDomain roleDomain = RoleDomain.builder()
                                      .name("ROLE_USER")
                                      .build();
    roleDomainRepository.save(roleDomain);

    List<UserDomain> userDomains = List.of(UserDomain.builder()
                                                     .username("user1")
                                                     .password("{noop}user1")
                                                     .enabled2Fa(false)
                                                     .build(),
                                           UserDomain.builder()
                                                     .username("user2")
                                                     .password("{noop}user2")
                                                     .enabled2Fa(true)
                                                     .build());
    userDomainRepository.saveAll(userDomains);

    List<UserRoleDomain> userRoleDomains = List.of(UserRoleDomain.builder()
                                                                 .roleId(roleDomain.getId())
                                                                 .userId(userDomains.get(0).getId())
                                                                 .build(),
                                                   UserRoleDomain.builder()
                                                                 .roleId(roleDomain.getId())
                                                                 .userId(userDomains.get(1).getId())
                                                                 .build());

    userRoleDomainRepository.saveAll(userRoleDomains);
  }
}
