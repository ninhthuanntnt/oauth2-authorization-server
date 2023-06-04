package com.ntnt.microservices.oauth2.authorization.server.security;

import com.ntnt.microservices.oauth2.authorization.server.domain.UserDomain;
import com.ntnt.microservices.oauth2.authorization.server.exception.NotFoundException;
import com.ntnt.microservices.oauth2.authorization.server.helper.MfaHelper;
import com.ntnt.microservices.oauth2.authorization.server.repository.UserDomainRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@RequiredArgsConstructor
public class MfaAuthenticationProvider implements AuthenticationProvider {
  private final UserDomainRepository userDomainRepository;
  private final MfaHelper mfaHelper;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    MfaAuthenticationToken mfaAuthenticationToken = (MfaAuthenticationToken) authentication;
    UserDomain userDomain = userDomainRepository.findByUsername(mfaAuthenticationToken.getName())
                                                .orElseThrow(() -> new NotFoundException(UserDomain.class));

    if (mfaHelper.verifyCode(userDomain.getMfaSecret(), mfaAuthenticationToken.getCode())) {
      return mfaAuthenticationToken.getDelegateAuthentication();
    }
    return null;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return MfaAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
