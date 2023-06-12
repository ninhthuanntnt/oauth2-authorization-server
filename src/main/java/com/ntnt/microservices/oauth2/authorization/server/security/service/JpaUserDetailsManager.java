package com.ntnt.microservices.oauth2.authorization.server.security.service;

import com.ntnt.microservices.oauth2.authorization.server.domain.UserDomain;
import com.ntnt.microservices.oauth2.authorization.server.repository.UserDomainRepository;
import com.ntnt.microservices.oauth2.authorization.server.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service("userDetailsService")
public class JpaUserDetailsManager implements UserDetailsService, UserDetailsPasswordService {
  private final UserDomainRepository userDomainRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return
        userDomainRepository
            .getByUsernameOrEmail(username)
            .map((UserDomain userDomain) ->
                     new CustomUserDetails(userDomain.getId(),
                                           userDomain.getUsername(),
                                           userDomain.getPassword(),
                                           userDomain.getUserRoles()
                                                       .stream()
                                                       .map(userRole -> new SimpleGrantedAuthority(userRole.getRole().getName()))
                                                       .collect(Collectors.toList()),
                                           userDomain.isEnabledMfa()))
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }

  @Override
  public UserDetails updatePassword(UserDetails user, String newPassword) {
    return user;
  }
}
