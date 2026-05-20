package com.application.authentication.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleUpgradeRequest {

    @Id
    private String requestId;

    @Column(nullable = false)
    private String userId;           // who requested

    @Column(nullable = false)
    private String username;      // who requested

    @Column(nullable = false)
    private String fromRole;         // ROLE_CUSTOMER

    @Column(nullable = false)
    private String toRole;           // ROLE_ADMIN

    @Column(nullable = false)
    private String status;           // PENDING / APPROVED / REJECTED

    private String reviewedBy;       // delegate/admin username
    private LocalDateTime createdAt;
    private LocalDateTime reviewedAt;

    private String reason;

}
