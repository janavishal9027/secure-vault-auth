package com.application.authentication.dtos;

import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * The editable part of a profile, and only that.
 *
 * <p>Username and email are deliberately absent. The username is the JWT
 * subject, so changing it invalidates the caller's own token mid-request; the
 * email is the account key that OAuth logins are matched on, so changing it
 * can silently detach a federated account from its provider. Both are
 * legitimate features, but they need token re-issue and a verification step
 * respectively — not a field on a general-purpose PATCH.</p>
 *
 * <p>Null means "leave alone" rather than "clear". Clearing is expressed as an
 * empty string, which lets the UI remove an avatar without a second endpoint.</p>
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UpdateProfileRequest {

    @Size(max = 80, message = "Display name must be at most 80 characters")
    private String displayName;

    /**
     * A provider URL or a data URI. Length is checked in the service rather
     * than here: the limit is a byte budget on the decoded image, which a
     * character-count annotation would express only approximately.
     */
    private String avatarUrl;
}
