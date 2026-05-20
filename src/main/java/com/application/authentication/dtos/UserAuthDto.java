package com.application.authentication.dtos;

import com.application.authentication.model.Roles;
import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserAuthDto {

    private String userId;
    private String username;
    private String email;
    private String password;
    private boolean accountNonLocked = true;
    private boolean accountNonExpired = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;
    private LocalDate credentialsExpiryDate;
    private LocalDate accountExpiryDate;
    private String twoFactorSecret;
    private boolean isTwoFactorEnabled = true;
    private String signUpMethod;
    private List<RoleRespDto> roles;
    private LocalDateTime createdDate;
    private LocalDateTime updatedDate;

}
