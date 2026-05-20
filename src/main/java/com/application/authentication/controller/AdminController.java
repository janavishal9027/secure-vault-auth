package com.application.authentication.controller;

import com.application.authentication.feignService.RolesClient;
import com.application.authentication.repository.UserRepository;
import com.application.authentication.service.UserAuthentication;
import com.application.authentication.service.UserAuthenticationService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final RolesClient rolesClient;

//    private final UserAuthenticationService userAuthService;
//
//    private final UserRepository userRepository;
//
//    private final UserAuthentication userAuthentication;

    // ✅ only ADMIN can assign role to any user
    @PostMapping("/assign-role")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<String> assignRole(@RequestParam String userId,
                                             @RequestParam String roleType) {

        if (roleType == null || roleType.isBlank() || !roleType.startsWith("ROLE_")) {
            return ResponseEntity.badRequest().body("Invalid roleType. Must start with ROLE_");
        }

        rolesClient.createUserRoleMapping("MY_SUPER_SECRET_KEY", roleType, userId);
        return ResponseEntity.ok("Role assigned: " + roleType + " to userId=" + userId);
    }

}
