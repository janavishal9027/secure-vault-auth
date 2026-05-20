package com.application.authentication.configuration;

import com.application.authentication.dtos.RoleRespDto;
import com.application.authentication.feignService.RolesClient;
import com.application.authentication.model.Roles;
import com.application.authentication.model.Users;
import com.application.authentication.repository.UserRepository;
import com.application.authentication.service.JwtService;
import com.application.authentication.service.UserAuthenticationService;
import com.application.authentication.service.UserDetailImpl;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Autowired
    private UserAuthenticationService userAuthenticationService;

    @Autowired
    private JwtService jwtService;

    @Value("${frontend.url}")
    private String frontendUrl;

    String username;
    String idAttributeKey;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RolesClient rolesClient;

    @Value("${internal.role-service-key}")
    private String internalKey;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String provider = oauthToken.getAuthorizedClientRegistrationId(); // github/google

        DefaultOAuth2User principal = (DefaultOAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = principal.getAttributes();

        String email = Objects.toString(attributes.getOrDefault("email", ""), "");
        if (email.isBlank()) {
            throw new RuntimeException("OAuth login failed: email not provided by " + provider);
        }

        // ✅ compute username locally (no class fields)
        String username;
        if ("github".equals(provider)) {
            username = Objects.toString(attributes.getOrDefault("login", ""), "");
        } else { // google
            username = email.split("@")[0];
        }

        // ✅ find or create user
        Users user = userRepository.findByEmail(email).orElseGet(() -> {
            LocalDateTime now = LocalDateTime.now();
            Users newUser = new Users();
            newUser.setUserId("AUTH" + now.getYear() + now.getDayOfYear() + now.getSecond() + now.getNano());
            newUser.setEmail(email);
            newUser.setUsername(username);
            newUser.setSignUpMethod(provider);

            newUser.setAccountExpiryDate(LocalDate.now().plusYears(1));
            newUser.setAccountNonExpired(true);
            newUser.setAccountNonLocked(true);
            newUser.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            newUser.setCredentialsNonExpired(true);
            newUser.setEnabled(true);
            newUser.setTwoFactorEnabled(false);
            newUser.setRoles(new ArrayList<>());

            newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));

            Users saved = userAuthenticationService.registerUser(newUser);

            // ✅ DEFAULT ROLE for all OAuth users
            rolesClient.createUserRoleMapping(internalKey, "ROLE_CUSTOMER", saved.getUserId());

            return saved;
        });

        // ✅ Always get roles from roles-service (since roles is @Transient)
        List<RoleRespDto> roles = rolesClient.getRolesByUserId(user.getUserId());
        List<String> roleTypes = (roles == null || roles.isEmpty())
                ? List.of("ROLE_CUSTOMER")
                : roles.stream().map(RoleRespDto::getRoleType).toList();

        // ✅ Create authorities from roleTypes
        Set<SimpleGrantedAuthority> authorities = roleTypes.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        // ✅ Generate JWT (use fixed JwtService that stores roles as List)
        UserDetailImpl userDetails = new UserDetailImpl(
                user.getUserId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                user.isTwoFactorEnabled(),
                authorities
        );

        String jwtToken = jwtService.generateTokenFromUsername(userDetails);

        // ✅ Redirect
        this.setAlwaysUseDefaultTargetUrl(true);
        String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl + "/notes/oauth2/redirect")
                .queryParam("token", jwtToken)
                .build().toUriString();

        this.setDefaultTargetUrl(targetUrl);
        super.onAuthenticationSuccess(request, response, authentication);
    }

}
