package com.application.authentication.controller;

import com.application.authentication.dtos.RoleUpgradeCreateRequest;
import com.application.authentication.dtos.RoleUpgradeResponse;
import com.application.authentication.service.RoleUpgradeService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/role-upgrade")
@SecurityRequirement(name = "bearerAuth")
public class RoleUpgradeController {

    @Autowired
    private RoleUpgradeService roleUpgradeService;

    // CUSTOMER -> raise request
    @PostMapping("/request-admin")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<RoleUpgradeResponse> requestAdmin(
            @RequestBody(required = false) RoleUpgradeCreateRequest body
    ) {
        return ResponseEntity.ok(roleUpgradeService.requestAdmin(body));
    }

    // CUSTOMER -> view own requests
    @GetMapping("/myRequests")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<RoleUpgradeResponse>> myRequests() {
        return ResponseEntity.ok(roleUpgradeService.myRequests());
    }

    // DELEGATE -> view pending
    @GetMapping("/pending")
    @PreAuthorize("hasRole('DELEGATE')")
    public ResponseEntity<List<RoleUpgradeResponse>> pending() {
        return ResponseEntity.ok(roleUpgradeService.pendingRequests());
    }

    // DELEGATE -> approve
    @PostMapping("/approve")
    @PreAuthorize("hasRole('DELEGATE')")
    public ResponseEntity<RoleUpgradeResponse> approve(@RequestParam String requestId) {
        return ResponseEntity.ok(roleUpgradeService.approve(requestId));
    }

    // DELEGATE -> reject
    @PostMapping("/reject")
    @PreAuthorize("hasRole('DELEGATE')")
    public ResponseEntity<RoleUpgradeResponse> reject(@RequestParam String requestId) {
        return ResponseEntity.ok(roleUpgradeService.reject(requestId));
    }

}
