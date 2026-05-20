package com.application.authentication.controller;

import com.application.authentication.dtos.UserAuthDto;
import com.application.authentication.dtos.UserDto;
import com.application.authentication.model.Users;
import com.application.authentication.repository.UserRepository;
import com.application.authentication.request.LoginRequest;
import com.application.authentication.request.SignUpRequest;
import com.application.authentication.service.JwtService;
import com.application.authentication.service.TotpService;
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
     * Token validation endpoint - useful for gateway or frontend.
     * Keep public if your gateway needs it.
     */
    @GetMapping("/public/validate")
    public Boolean validateToken(@RequestParam String token){
        return userAuthService.validateToken(token);
    }

    @GetMapping("/public/extractUserId")
    public String extractUserId(@RequestParam String token) {
        return userAuthService.extractUserIdFromToken(token);
    }

    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<String> verify2FALogin(@RequestParam int code, @RequestParam String jwtToken){
        String username = jwtService.getUsernameFromJwtToken(jwtToken);
        Users user = userAuthService.findByUsername(username);
        boolean isValid = userAuthService.verify2FASecret(user.getUserId(), code);
        if(isValid){
            return ResponseEntity.ok("2FA Verified Successfully");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid 2FA Code");
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
}
