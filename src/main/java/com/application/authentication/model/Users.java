package com.application.authentication.model;

import com.application.authentication.dtos.RoleRespDto;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "username"),
                @UniqueConstraint(columnNames = "email")
        })
public class Users {
    @Id
    @Column(name = "user_id")
    private String userId;

    @NotBlank
    @Size(max = 20)
    @Column(name = "username")
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    @Column(name = "email")
    private String email;

    @Size(max = 120)
    @Column(name = "password")
    @JsonIgnore
    private String password;

    private boolean accountNonLocked = true;
    private boolean accountNonExpired = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;

    private LocalDate credentialsExpiryDate;
    private LocalDate accountExpiryDate;

    // The TOTP seed is a credential in its own right — anyone holding it can
    // generate valid 2FA codes. It must never reach a response body.
    @JsonIgnore
    private String twoFactorSecret;

    private boolean isTwoFactorEnabled = false;
    private String signUpMethod;

    /**
     * Friendly name shown in the UI. Seeded from the OAuth provider's "name"
     * claim at first login and editable afterwards; falls back to the username
     * when never set, so it is safe for this to be null on older rows.
     */
    @Size(max = 80)
    @Column(name = "display_name")
    private String displayName;

    /**
     * Either a provider-hosted URL (Google's "picture", GitHub's "avatar_url")
     * captured at first OAuth login, or a data URI for an avatar the user
     * uploaded themselves.
     *
     * <p>TEXT rather than a bounded varchar because a data URI is the whole
     * image inline. The upload path downscales before encoding and the write
     * endpoint enforces a hard size limit — this column is not a place to put
     * an arbitrary file.</p>
     */
    @Column(name = "avatar_url", columnDefinition = "TEXT")
    private String avatarUrl;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdDate;

    @UpdateTimestamp
    private LocalDateTime updatedDate;

    @Transient
    private List<RoleRespDto> roles;
}
