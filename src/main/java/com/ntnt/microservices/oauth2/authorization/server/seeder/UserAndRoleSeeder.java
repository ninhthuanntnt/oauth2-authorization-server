package com.ntnt.microservices.oauth2.authorization.server.seeder;

import com.ntnt.microservices.oauth2.authorization.server.domain.RoleDomain;
import com.ntnt.microservices.oauth2.authorization.server.domain.UserDomain;
import com.ntnt.microservices.oauth2.authorization.server.domain.UserRoleDomain;
import com.ntnt.microservices.oauth2.authorization.server.repository.RoleDomainRepository;
import com.ntnt.microservices.oauth2.authorization.server.repository.UserDomainRepository;
import com.ntnt.microservices.oauth2.authorization.server.repository.UserRoleDomainRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@RequiredArgsConstructor
@Component
public class UserAndRoleSeeder implements CommandLineRunner {
  private final UserDomainRepository userDomainRepository;
  private final UserRoleDomainRepository userRoleDomainRepository;
  private final RoleDomainRepository roleDomainRepository;
  private final PasswordEncoder passwordEncoder;

  @Override
  public void run(String... args) throws Exception {
    RoleDomain roleDomain = RoleDomain.builder()
                                      .name("ROLE_USER")
                                      .build();
    roleDomainRepository.save(roleDomain);

    List<UserDomain> userDomains = List.of(UserDomain.builder()
                                                     .username("user1")
                                                     .password(passwordEncoder.encode("user1"))
                                                     .enabledMfa(false)
                                                     .build(),
                                           UserDomain.builder()
                                                     .username("user2")
                                                     .password(passwordEncoder.encode("user2"))
                                                     .enabledMfa(true)
                                                     .mfaSecret("BODFUWND47EX3OIHUZIYKG4OGKQR7W4B")
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
