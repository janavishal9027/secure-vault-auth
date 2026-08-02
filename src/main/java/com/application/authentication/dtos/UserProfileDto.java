package com.application.authentication.dtos;

import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

/**
 * What the signed-in user is allowed to see about themselves.
 *
 * <p>Separate from {@link UserAuthDto} on purpose. That one is the shape of a
 * user as seen by <em>someone else</em> (the lookup endpoints), and carries
 * account-lifecycle flags that are an administrator's concern. This one is the
 * self view that backs the Settings screen: identity, profile, and the two
 * facts the UI needs to decide what it may offer — whether 2FA is on, and
 * whether the account is password-based or federated.</p>
 *
 * <p>Neither DTO carries the password hash or the TOTP seed.</p>
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserProfileDto {

    private String userId;
    private String username;
    private String email;
    private String displayName;
    private String avatarUrl;

    /**
     * "email" for a local signup, otherwise the provider id ("google",
     * "github"). The UI uses this to explain why the password section is
     * absent for federated accounts rather than silently hiding it.
     */
    private String signUpMethod;

    private boolean twoFactorEnabled;
    private List<RoleRespDto> roles;
    private LocalDateTime createdDate;
}
