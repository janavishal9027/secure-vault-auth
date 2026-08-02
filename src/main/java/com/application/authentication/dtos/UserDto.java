package com.application.authentication.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {

    private String username;
    private String jwtToken;
    private List<String> roles;

    /**
     * True when {@code jwtToken} is only a 2FA challenge token: the password
     * checked out, but the token grants nothing until the caller posts a valid
     * TOTP code to /api/user/public/verify-2fa-login and swaps it for a real one.
     */
    private boolean mfaRequired;

}
