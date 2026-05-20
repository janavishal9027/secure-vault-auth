package com.application.authentication.service;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

public interface TotpService {

    GoogleAuthenticatorKey generateSecret();

    String getQrCodeUrl(GoogleAuthenticatorKey secret, String username);

    boolean verifySecret(String secret, int code);

}
