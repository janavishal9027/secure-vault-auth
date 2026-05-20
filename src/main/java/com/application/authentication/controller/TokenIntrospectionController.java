package com.application.authentication.controller;

import com.application.authentication.dtos.TokenIntrospectionResponse;
import com.application.authentication.request.LoginRequest;
import com.application.authentication.service.JwtService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
public class TokenIntrospectionController {

    private final JwtService jwtService;

    @GetMapping("/public/introspect")
    public ResponseEntity<TokenIntrospectionResponse> introspect(
            @RequestHeader(value = "Authorization", required = false) String authHeader
    ) {

        if (authHeader == null || authHeader.isBlank()) {
            return ResponseEntity.ok(
                    TokenIntrospectionResponse.builder()
                            .active(false)
                            .build()
            );
        }

        String token = authHeader.startsWith("Bearer ")
                ? authHeader.substring(7)
                : authHeader;

        try {
            String username = jwtService.getUsernameFromToken(token);

            boolean valid = jwtService.validateToken(
                    token,
                    LoginRequest.builder().username(username).build()
            );

            if (!valid) {
                return ResponseEntity.ok(
                        TokenIntrospectionResponse.builder()
                                .active(false)
                                .build()
                );
            }

            List<String> roles = jwtService.getRolesFromToken(token);

            return ResponseEntity.ok(
                    TokenIntrospectionResponse.builder()
                            .active(true)
                            .username(username)
                            .roles(roles)
                            .build()
            );

        } catch (Exception e) {
            return ResponseEntity.ok(
                    TokenIntrospectionResponse.builder()
                            .active(false)
                            .build()
            );
        }
    }
}
