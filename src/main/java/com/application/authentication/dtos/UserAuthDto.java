package com.application.authentication.dtos;

import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Outbound view of a user. Deliberately carries neither the password hash nor
 * the TOTP seed: this DTO is returned by the user-lookup endpoints, and both
 * fields would hand an attacker everything needed to crack the credential
 * offline and mint valid 2FA codes.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserAuthDto {

    private String userId;
    private String username;
    private String email;
    private boolean accountNonLocked = true;
    private boolean accountNonExpired = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;
    private LocalDate credentialsExpiryDate;
    private LocalDate accountExpiryDate;
    private boolean isTwoFactorEnabled = true;
    private String signUpMethod;
    private List<RoleRespDto> roles;
    private LocalDateTime createdDate;
    private LocalDateTime updatedDate;

}
