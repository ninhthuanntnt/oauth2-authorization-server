package com.ntnt.microservices.oauth2.authorization.server.helper;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.util.Utils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class MfaHelper {
  private final SecretGenerator secretGenerator;
  private final QrDataFactory qrDataFactory;
  private final QrGenerator qrGenerator;
  private final CodeVerifier codeVerifier;
  private final RecoveryCodeGenerator recoveryCodeGenerator;

  public String generateSecretKey() {
    return secretGenerator.generate();
  }

  public String getQRCode(String secret, String label) throws QrGenerationException {
    QrData data = qrDataFactory.newBuilder()
                               .label(label)
                               .secret(secret)
                               .issuer("NTNT OAuthorization Server")
                               .build();
    return Utils.getDataUriForImage(
        qrGenerator.generate(data),
        qrGenerator.getImageMimeType());
  }

  public boolean verifyCode(String secret, String code) {
    return codeVerifier.isValidCode(secret, code);
  }

  public String generateRecoveryCodes() {
    return String.join("-", recoveryCodeGenerator.generateCodes(5));
  }
}
