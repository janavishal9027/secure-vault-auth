package com.application.authentication.service;

import com.application.authentication.dtos.*;
import com.application.authentication.exceptions.ClientConnectException;
import com.application.authentication.feignService.RolesClient;
import com.application.authentication.model.Users;
import com.application.authentication.repository.UserRepository;
import com.application.authentication.request.DelegateSignUpRequest;
import com.application.authentication.request.LoginRequest;
import com.application.authentication.request.SignUpRequest;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import feign.FeignException;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class UserAuthenticationService implements UserAuthentication {

    @Autowired
    private RolesClient rolesClient;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ModelMapper modelMapper;

    @Autowired
    private TotpService totpService;

    @Value("${internal.role-service-key}")
    private String internalKey;

    @Value("${delegate.bootstrap.key}")
    private String delegateBootstrapKey;

    @Value("${delegate.bootstrap.allow-first-only:true}")
    private boolean allowFirstDelegateOnly;

    private static final Logger log = LoggerFactory.getLogger(UserAuthenticationService.class);

    @Override
    public UserAuthDto signUpUser(SignUpRequest signUpRequest){

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        LocalDateTime now = LocalDateTime.now();
        String userId = "AUTH" + now.getYear() + now.getDayOfYear() + now.getSecond() + now.getNano();

        Users users = new Users();
        users.setUserId(userId);
        users.setUsername(signUpRequest.getUsername());
        users.setEmail(signUpRequest.getEmail());
        users.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        users.setCreatedDate(now);
        users.setUpdatedDate(now);
        users.setAccountNonLocked(true);
        users.setAccountNonExpired(true);
        users.setCredentialsNonExpired(true);
        users.setEnabled(true);
        // Default Role
        users.setRoles(List.of(RoleRespDto.builder()
                .roleType("ROLE_CUSTOMER")
                .build()));
        users.setCredentialsExpiryDate(LocalDate.now().plusMonths(6));
        users.setAccountExpiryDate(LocalDate.now().plusMonths(6));
        users.setTwoFactorEnabled(false);
        users.setSignUpMethod("email");

        Users save = userRepository.save(users);

        try {
            // Always assign default role
            rolesClient.assignDefaultRole(save.getUserId());
        } catch (Exception e) {
            log.error("Role assignment failed for userId={}", save.getUserId(), e);
            throw new RuntimeException("User created but role assignment failed");
        }

        List<RoleRespDto> roles;
        try {
            roles = rolesClient.getRolesByUserId(save.getUserId());
        } catch (ClientConnectException e) {
            log.error("Unable to fetch roles for userId={}", save.getUserId(), e);
            roles = new ArrayList<>();
        }

        UserAuthDto dto = modelMapper.map(save, UserAuthDto.class);
        dto.setRoles(roles);

        log.info("User registered successfully: {}", dto);
        return dto;
    }

    @Override
    public UserAuthDto signUpDelegate(DelegateSignUpRequest request, String bootstrapKey) {

        validateBootstrapKey(bootstrapKey);
        validateDelegateCreationAllowed();
        validateUniqueUser(request.getUsername(), request.getEmail());

        Users user = buildUser(
                request.getUsername(),
                request.getEmail(),
                request.getPassword()
        );

        Users savedUser = userRepository.save(user);

        try {
            rolesClient.createUserRoleMapping(internalKey, "DELEGATE", savedUser.getUserId());

            List<RoleRespDto> roles = fetchRolesSafely(savedUser.getUserId());

            UserAuthDto dto = modelMapper.map(savedUser, UserAuthDto.class);
            dto.setRoles(roles);

            log.info("Delegate registered successfully with userId={}", savedUser.getUserId());
            return dto;

        } catch (Exception e) {
            log.error("Delegate role assignment failed for userId={}", savedUser.getUserId(), e);

            // rollback local user creation if role mapping fails
            userRepository.deleteById(savedUser.getUserId());

            throw new RuntimeException("Delegate signup failed because role assignment failed");
        }
    }

    private void validateBootstrapKey(String bootstrapKey) {
        if (bootstrapKey == null || bootstrapKey.isBlank() || !delegateBootstrapKey.equals(bootstrapKey)) {
            throw new RuntimeException("Invalid delegate bootstrap key");
        }
    }

    private void validateDelegateCreationAllowed() {
        if (allowFirstDelegateOnly) {
            try {
                Long delegateCount = rolesClient.countDelegates(internalKey);

                if (delegateCount != null && delegateCount > 0) {
                    throw new RuntimeException("Delegate already exists. Private delegate signup is disabled.");
                }
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                log.error("Unable to count delegates", e);
                throw new RuntimeException("Unable to validate delegate signup");
            }
        }
    }

    private void validateUniqueUser(String username, String email) {
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Username already exists");
        }
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email already exists");
        }
    }

    private Users buildUser(String username, String email, String rawPassword) {
        LocalDateTime now = LocalDateTime.now();
        String userId = "AUTH" + now.getYear() + now.getDayOfYear() + now.getSecond() + now.getNano();

        Users user = new Users();
        user.setUserId(userId);
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setCreatedDate(now);
        user.setUpdatedDate(null);
        user.setAccountNonLocked(true);
        user.setAccountNonExpired(true);
        user.setCredentialsNonExpired(true);
        user.setEnabled(true);
        user.setCredentialsExpiryDate(LocalDate.now().plusMonths(6));
        user.setAccountExpiryDate(LocalDate.now().plusMonths(6));
        user.setTwoFactorEnabled(false);
        user.setSignUpMethod("email");
        user.setRoles(new ArrayList<>());

        return user;
    }

    private List<RoleRespDto> fetchRolesSafely(String userId) {
        try {
            List<RoleRespDto> roles = rolesClient.getRolesByUserId(userId);
            return roles != null ? roles : new ArrayList<>();
        } catch (Exception e) {
            log.error("Unable to fetch roles for userId={}", userId, e);
            return new ArrayList<>();
        }
    }

    @Override
    public UserDto loginUser(LoginRequest loginRequest){
        Users user = userRepository.findByUsername(loginRequest.getUsername())
            .orElseThrow(() -> new BadCredentialsException("Invalid username or password"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }

        if (!user.isEnabled()) {
            throw new RuntimeException("Account is disabled");
        }

        if (!user.isAccountNonLocked()) {
            throw new RuntimeException("Account is locked");
        }

        if (!user.isAccountNonExpired()) {
            throw new RuntimeException("Account is expired");
        }

        if (!user.isCredentialsNonExpired()) {
            throw new RuntimeException("Credentials expired");
        }

        List<RoleRespDto> roles;
        try {
            roles = rolesClient.getRolesByUserId(user.getUserId());
        } catch (FeignException e) {
            throw new ClientConnectException("Unable to fetch roles from Roles Service");
        }

        List<String> roleTypes = (roles == null || roles.isEmpty())
                ? List.of("ROLE_CUSTOMER")
                : roles.stream()
                .map(RoleRespDto::getRoleType)
                .map(String::toUpperCase)
                .toList();

        // Generate JWT
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roleTypes);
        claims.put("username", user.getUsername());
        claims.put("userId", user.getUserId());

        String token = jwtService.generateToken(claims, loginRequest);

        return UserDto.builder()
                .username(user.getUsername())
                .jwtToken(token)
                .roles(roleTypes)
                .build();
    }

    @Override
    public String prepareJwtClaimAndGenerateToken(List<String> roles, LoginRequest loginRequest){
        Map<String, Object> jwtClaims = new HashMap<>();
        jwtClaims.put("roles", roles);
        jwtClaims.put("username", loginRequest.getUsername());
        return jwtService.generateToken(jwtClaims, loginRequest);
    }

    @Override
    public Boolean validateToken(String token){
        String refKeyFromToken = jwtService.getRefKeyFromToken(token);
        Users user = userRepository.findByUsername(refKeyFromToken).orElseThrow(() -> new UsernameNotFoundException("User not found with Username: " + refKeyFromToken));
        return jwtService.validateToken(token, LoginRequest.builder().username(user.getUsername()).build());
    }

    @Override
    public String extractUserIdFromToken(String token){
        String refKeyFromToken = jwtService.getRefKeyFromToken(token);
        Users user = userRepository.findByUsername(refKeyFromToken).orElseThrow(() -> new UsernameNotFoundException("User not found with Username: " + refKeyFromToken));
        return user.getUserId();
    }

    @Override
    public List<Users> getAllUsers(){
        return userRepository.findAll();
    }

    @Override
    public UserDto getUserById(String userId){
        Users users = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        return modelMapper.map(users, UserDto.class);
    }

    @Override
    public UserAuthDto getUserByUserId(String userId){
        Users users = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        users.setRoles(rolesClient.getRolesByUserId(users.getUserId()));
        return modelMapper.map(users, UserAuthDto.class);
    }

    @Override
    public UserAuthDto getUserByUsername(String username){
        Users users = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        users.setRoles(rolesClient.getRolesByUserId(users.getUserId()));
        return modelMapper.map(users, UserAuthDto.class);
    }

    @Override
    public Users findByUsername(String username) {
        Optional<Users> byUsername = userRepository.findByUsername(username);
        return byUsername.orElseThrow(()-> new UsernameNotFoundException("User not found with username: " + username));
    }


    @Override
    public void updateAccountLockStatus(String userId, boolean lockStatus){
        Users users = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        users.setAccountNonLocked(!lockStatus);
        userRepository.save(users);
    }

    @Override
    public void updateAccountExpiryStatus(String userId, boolean expiryStatus){
        Users users = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        users.setAccountNonExpired(!expiryStatus);
        userRepository.save(users);
    }

    @Override
    public void updateAccountEnabledStatus(String userId, boolean enabledStatus){
        Users users = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        users.setEnabled(enabledStatus);
        userRepository.save(users);
    }

    @Override
    public void updateCredentialsExpiryStatus(String userId, boolean expiryStatus){
        Users users = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        users.setCredentialsNonExpired(!expiryStatus);
        userRepository.save(users);
    }

    @Override
    public Optional<Users> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public Users registerUser(Users users) {
        if(users.getPassword() != null) {
            users.setPassword(passwordEncoder.encode(users.getPassword()));
        }
        return userRepository.save(users);
    }

    @Override
    public GoogleAuthenticatorKey generate2FASecret(String userId){
        Users users = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        GoogleAuthenticatorKey key = totpService.generateSecret();
        users.setTwoFactorSecret(key.getKey());
        userRepository.save(users);
        return key;
    }

    @Override
    public boolean verify2FASecret(String userId, int code){
        Users users = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        return totpService.verifySecret(users.getTwoFactorSecret(), code);
    }

    @Override
    public void enable2FA(String userId){
        Users users = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        users.setTwoFactorEnabled(true);
        userRepository.save(users);
    }

    @Override
    public void disable2FA(String userId){
        Users users = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        users.setTwoFactorEnabled(false);
        userRepository.save(users);
    }

}
