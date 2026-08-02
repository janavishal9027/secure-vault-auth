package com.application.authentication.controller;

import com.application.authentication.dtos.UpdateProfileRequest;
import com.application.authentication.dtos.UserAuthDto;
import com.application.authentication.dtos.UserDto;
import com.application.authentication.model.Users;
import com.application.authentication.repository.UserRepository;
import com.application.authentication.request.LoginRequest;
import com.application.authentication.request.SignUpRequest;
import com.application.authentication.service.JwtService;
import com.application.authentication.service.TotpService;
import com.application.authentication.service.UserDetailImpl;
import com.application.authentication.service.UserAuthentication;
import com.application.authentication.service.UserAuthenticationService;
import com.application.authentication.utils.ApiResponse;
import com.application.authentication.utils.AuthUtils;
import com.application.authentication.utils.Constants;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserAuthController {

    @Autowired
    private UserAuthenticationService userAuthService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ModelMapper modelMapper;

    @Autowired
    private AuthUtils authUtils;

    @Autowired
    private TotpService totpService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserAuthentication userAuthentication;

    @Autowired
    private UserDetailsService userDetailsService;


    // -------------------------
    // PUBLIC ENDPOINTS
    // -------------------------

    @PostMapping("/public/signUp")
    public ResponseEntity<?> register(@Valid @RequestBody SignUpRequest signUpRequest){

        UserAuthDto registeredUser = userAuthService.signUpUser(signUpRequest);
        Users map = modelMapper.map(registeredUser, Users.class);

        return new ResponseEntity<>(new ApiResponse(Constants.SUCCESS.name(), map, "User Creation successfully"), HttpStatus.CREATED);
    }

    @PostMapping("/public/login")
    public UserDto login(@RequestBody LoginRequest loginRequest) {
        return userAuthService.loginUser(loginRequest);
    }

    /**
     * Token validation endpoint - used server-to-server by the notes service.
     *
     * The token travels in the Authorization header, never as a query
     * parameter: query strings land in access logs, proxy logs and browser
     * history, which is no place for a live credential.
     */
    @GetMapping("/public/validate")
    public Boolean validateToken(@RequestHeader("Authorization") String authorization){
        return userAuthService.validateToken(stripBearer(authorization));
    }

    @GetMapping("/public/extractUserId")
    public String extractUserId(@RequestHeader("Authorization") String authorization) {
        return userAuthService.extractUserIdFromToken(stripBearer(authorization));
    }

    private String stripBearer(String authorization) {
        if (authorization == null || authorization.isBlank()) {
            throw new BadCredentialsException("Missing Authorization header");
        }
        return authorization.startsWith("Bearer ") ? authorization.substring(7) : authorization;
    }

    /**
     * Second leg of a 2FA login: swaps the challenge token issued by /login
     * for a real access token. Until this succeeds the caller holds nothing
     * usable.
     */
    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<?> verify2FALogin(@RequestParam int code, @RequestParam String jwtToken){
        try {
            return ResponseEntity.ok(userAuthService.completeTwoFactorLogin(jwtToken, code));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid 2FA Code"));
        }
    }

    // -------------------------
    // 2FA (Authenticated)
    // -------------------------

    //2FA Authentication
    @PostMapping("/enable-2fa")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<String> enable(){
        String string = authUtils.loggedInUserId();
        GoogleAuthenticatorKey key = userAuthService.generate2FASecret(string);
        String qrCode = totpService.getQrCodeUrl(key, userAuthService.getUserById(string).getUsername());
        return ResponseEntity.ok(qrCode);
    }

    @PostMapping("/disable-2fa")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<String> disable(){
        String userId = String.valueOf(authUtils.loggedInUserId());
        userAuthService.disable2FA(userId);
        return ResponseEntity.ok("2FA disabled Successfully");
    }

    @PostMapping("/verify-2fa")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<String> verify(@RequestParam int code){
        String userId = String.valueOf(authUtils.loggedInUserId());
        boolean isValid = userAuthService.verify2FASecret(userId, code);
        if(isValid){
            userAuthService.enable2FA(userId);
            return ResponseEntity.ok("2FA Verified Successfully");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid 2FA Code");
        }
    }

    @GetMapping("/2fa-status")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<?> get2FAStatus(){
        Users user = authUtils.loggedInUser();
        if(user!= null){
            return ResponseEntity.ok().body(Map.of("is2faEnabled", user.isTwoFactorEnabled()));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
    }

    @GetMapping("/allUsers")
    @PreAuthorize("hasRole('DELEGATE')")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<List<Users>> getAllUsers(){
        List<Users> allUsers = userAuthService.getAllUsers();
        return ResponseEntity.ok(allUsers);
    }

    @GetMapping("/getUserByUsername")
    @SecurityRequirement(name = "bearerAuth")
    public UserAuthDto getUserByUsername(@RequestParam String username){
        return userAuthService.getUserByUsername(username);
    }

    @GetMapping("/getUserByUserId")
    @SecurityRequirement(name = "bearerAuth")
    public UserAuthDto getUserByUserId(@RequestParam String userId) {
        return userAuthService.getUserByUserId(userId);
    }

    /**
     * Exchanges a still-valid token for a fresh one.
     *
     * <p>This is what turns the JWT lifetime from an <em>absolute</em> cap into
     * an <em>idle</em> one. Previously a session died 30 minutes after login no
     * matter what the user was doing, which is why someone mid-note could be
     * thrown back to the login screen. The client now renews while the user is
     * active, and simply stops renewing when they are not — so the same 30
     * minutes becomes "30 minutes of inactivity".</p>
     *
     * <p>Deliberately not a public endpoint and deliberately not accepting a
     * token in the body: the caller must already be authenticated, so an
     * expired token cannot be traded for a live one. Once the window lapses,
     * logging in again is the only way back.</p>
     */
    @PostMapping("/refresh-token")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<?> refreshToken() {
        String username = authUtils.loggedInUsername();
        if (username == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse(Constants.FAILED.name(), "Not authenticated"));
        }

        UserDetails details = userDetailsService.loadUserByUsername(username);
        if (!(details instanceof UserDetailImpl userDetails)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse(Constants.FAILED.name(), "Unable to refresh session"));
        }

        String token = jwtService.generateTokenFromUsername(userDetails);
        return ResponseEntity.ok(Map.of("jwtToken", token));
    }

    // -------------------------
    // SELF-SERVICE PROFILE
    // -------------------------

    /**
     * The caller's own profile.
     *
     * <p>Takes no identifier. The existing lookup endpoints accept a userId or
     * username from the query string, which makes them a poor fit for "show me
     * my settings" — the client would have to say who it is, and the server
     * would have to decide whether to believe it. Here the subject comes from
     * the authenticated principal, so there is nothing to authorise.</p>
     */
    @GetMapping("/me")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<?> getMyProfile() {
        String username = authUtils.loggedInUsername();
        if (username == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse(Constants.FAILED.name(), "Not authenticated"));
        }
        return ResponseEntity.ok(userAuthService.getMyProfile(username));
    }

    @PatchMapping("/me")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<?> updateMyProfile(@Valid @RequestBody UpdateProfileRequest request) {
        String username = authUtils.loggedInUsername();
        if (username == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse(Constants.FAILED.name(), "Not authenticated"));
        }
        try {
            return ResponseEntity.ok(userAuthService.updateMyProfile(username, request));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(Constants.FAILED.name(), ex.getMessage()));
        }
    }
}
