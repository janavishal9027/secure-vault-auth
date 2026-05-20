package com.application.authentication.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Service;

@Service
public class TotpServiceImpl implements TotpService {

    private final GoogleAuthenticator googleAuthenticator;

    public TotpServiceImpl(GoogleAuthenticator googleAuthenticator) {
        this.googleAuthenticator = googleAuthenticator;
    }

    public TotpServiceImpl() {
        this.googleAuthenticator = new GoogleAuthenticator();
    }

    @Override
    public GoogleAuthenticatorKey generateSecret() {
        return googleAuthenticator.createCredentials();
    }

    @Override
    public String getQrCodeUrl(GoogleAuthenticatorKey secret, String username) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL("Secure Notes", username, secret);
    }

    @Override
    public boolean verifySecret(String secret, int code) {
        return googleAuthenticator.authorize(secret, code);
    }

}
