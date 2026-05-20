package com.application.authentication.dtos;

import lombok.*;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TokenIntrospectionResponse {
    private boolean active;
    private String username;
    private List<String> roles;
}
