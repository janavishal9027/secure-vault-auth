package com.application.authentication.service;

import com.application.authentication.dtos.UserAuthDto;
import com.application.authentication.dtos.UserDto;
import com.application.authentication.model.Users;
import com.application.authentication.request.DelegateSignUpRequest;
import com.application.authentication.request.LoginRequest;
import com.application.authentication.request.SignUpRequest;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

import java.util.List;
import java.util.Optional;

public interface UserAuthentication {

    UserAuthDto signUpUser(SignUpRequest signUpRequest);

    UserAuthDto signUpDelegate(DelegateSignUpRequest request, String bootstrapKey);

    UserDto loginUser(LoginRequest loginRequest);

    String prepareJwtClaimAndGenerateToken(List<String> roles, LoginRequest loginRequest);

    Boolean validateToken(String token);

    List<Users> getAllUsers();

    UserDto getUserById(String userId);

    UserAuthDto getUserByUserId(String userId);

    UserAuthDto getUserByUsername(String username);

    Users findByUsername(String username);

    void updateAccountLockStatus(String userId, boolean lockStatus);

    void updateAccountExpiryStatus(String userId, boolean expiryStatus);

    void updateAccountEnabledStatus(String userId, boolean enabledStatus);

    void updateCredentialsExpiryStatus(String userId, boolean expiryStatus);

    Optional<Users> findByEmail(String email);

    Users registerUser(Users users);

    GoogleAuthenticatorKey generate2FASecret(String userId);

    boolean verify2FASecret(String userId, int code);

    void enable2FA(String userId);

    void disable2FA(String userId);

    String extractUserIdFromToken(String token);
}
