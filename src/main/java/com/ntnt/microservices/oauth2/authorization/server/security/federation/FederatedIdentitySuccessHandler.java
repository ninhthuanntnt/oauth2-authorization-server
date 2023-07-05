package com.ntnt.microservices.oauth2.authorization.server.security.federation;

import com.ntnt.microservices.oauth2.authorization.server.domain.UserDomain;
import com.ntnt.microservices.oauth2.authorization.server.domain.constant.IdentityProvider;
import com.ntnt.microservices.oauth2.authorization.server.repository.UserDomainRepository;
import com.ntnt.microservices.oauth2.authorization.server.security.CustomUserDetails;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class FederatedIdentitySuccessHandler implements AuthenticationSuccessHandler {
  private final AuthenticationSuccessHandler delegate;
  private final UserDomainRepository userDomainRepository;
  private final PasswordEncoder passwordEncoder;
  private final UserDetailsService userDetailsService;
  private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
  private final SessionRegistry sessionRegistry;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request,
                                      HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {
    if (authentication instanceof OAuth2AuthenticationToken) {
      saveUser(request, (OAuth2AuthenticationToken) authentication);
      oAuth2AuthorizedClientRepository.removeAuthorizedClient("google",
              SecurityContextHolder.getContext().getAuthentication(),
              request, response);
      delegate.onAuthenticationSuccess(request, response, authentication);
    }
  }

  private void saveUser(HttpServletRequest request, OAuth2AuthenticationToken oAuth2AuthenticationToken) {
    UserDomain userDomain = convertToUserDomain(oAuth2AuthenticationToken);
    UserDomain dbUserDomain = userDomainRepository.findByEmail(userDomain.getEmail())
            .orElseGet(() -> {
              while (userDomainRepository.existsByUsername(userDomain.getUsername())) {
                userDomain.setUsername(UUID.randomUUID().toString());
              }
              return userDomainRepository.save(userDomain);
            });

    CustomUserDetails customUserDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(dbUserDomain.getUsername());
    customUserDetails.eraseCredentials();
    sessionRegistry.registerNewSession(request.getSession().getId(), customUserDetails);
    SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(customUserDetails,
                                                                              null,
                                                                              customUserDetails.getAuthorities()));
  }

  private UserDomain convertToUserDomain (OAuth2AuthenticationToken oAuth2AuthenticationToken) {
    OAuth2User oAuth2User = oAuth2AuthenticationToken.getPrincipal();
    IdentityProvider identityProvider = IdentityProvider.valueOf(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()
                                                                                          .toUpperCase());
    String email = oAuth2User.getName();

    return UserDomain.builder()
                     .username(UUID.randomUUID().toString())
                     .email(email)
                     .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                     .identityProvider(identityProvider)
                     .build();
  }
}
