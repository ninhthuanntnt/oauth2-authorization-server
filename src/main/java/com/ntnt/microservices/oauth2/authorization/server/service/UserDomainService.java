package com.ntnt.microservices.oauth2.authorization.server.service;

import com.ntnt.microservices.oauth2.authorization.server.domain.UserDomain;
import com.ntnt.microservices.oauth2.authorization.server.exception.NotFoundException;
import com.ntnt.microservices.oauth2.authorization.server.helper.MfaHelper;
import com.ntnt.microservices.oauth2.authorization.server.repository.UserDomainRepository;
import com.ntnt.microservices.oauth2.authorization.server.util.SecurityUtil;
import dev.samstevens.totp.exceptions.QrGenerationException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserDomainService {
  private final UserDomainRepository userDomainRepository;
  private final PasswordEncoder passwordEncoder;
  private final MfaHelper mfaHelper;

  public UserDomain getCurrentUser() {
    return userDomainRepository.findById(SecurityUtil.getCurrentUserId())
                               .orElseThrow(() -> new NotFoundException(UserDomain.class));
  }

  public String setupMfa(boolean enabledMfa) {
    Long currentUserId = SecurityUtil.getCurrentUserId();

    UserDomain userDomain = userDomainRepository.findById(currentUserId)
                                                .orElseThrow(() -> new NotFoundException(UserDomain.class));

    if (enabledMfa==userDomain.isEnabledMfa()) {
      throw new RuntimeException("Mfa same status");
    }

    if (enabledMfa) {
      String secret = mfaHelper.generateSecretKey();

      userDomain.setEnabledMfa(true);
      userDomain.setMfaSecret(secret);

      try {
        String qrCode = mfaHelper.getQRCode(secret, userDomain.getUsername());
        userDomainRepository.save(userDomain);
        return qrCode;
      } catch (QrGenerationException e) {
        throw new RuntimeException("Cannot generate qr code");
      }
    } else {
      userDomain.setEnabledMfa(false);
      userDomain.setMfaSecret(null);
      userDomain.setMfaRecoveryCode(null);
      userDomainRepository.save(userDomain);
      return null;
    }
  }
}
