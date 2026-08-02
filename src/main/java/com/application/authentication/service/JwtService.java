package com.application.authentication.service;

import com.application.authentication.request.LoginRequest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Function;


@Service
public class JwtService {

    /**
     * Claim marking a token as a 2FA challenge: the password was accepted but
     * the second factor has not been presented yet. Every consumer of a token
     * must treat one carrying this claim as unauthenticated.
     */
    public static final String MFA_PENDING_CLAIM = "mfaPending";

    /** How long a user has to enter their TOTP code before re-authenticating. */
    private static final long MFA_CHALLENGE_TTL_MILLIS = 5 * 60 * 1000L;

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    //Token Parsing & Claim Extraction

    private Claims getAllClaimsFromToken(String token){
        return Jwts.parser().verifyWith((SecretKey) getSigningKey()).build().parseSignedClaims(token).getPayload();
    }

    public <T> T getClaimsFromToken(String token, Function<Claims, T> claimsResolver){
        Claims allClaimsFromToken = getAllClaimsFromToken(token);
        return claimsResolver.apply(allClaimsFromToken);
    }

    private Date extractExpiration(String token){
        return getClaimsFromToken(token, Claims::getExpiration);
    }

    public String getUsernameFromToken(String token){
        return getClaimsFromToken(token, Claims::getSubject);
    }

    public String getUsernameFromJwtToken(String token) {
        return Jwts.parser().verifyWith((SecretKey) getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    //Token Validation

    public boolean validateToken(String token, LoginRequest loginRequest){
        final String usernameFromToken = getUsernameFromToken(token);
        return (usernameFromToken.equals(loginRequest.getUsername())
                && isTokenNotExpired(token)
                && !isMfaPending(token));
    }

    private boolean isTokenNotExpired(String token){
        return !extractExpiration(token).before(new Date());
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        String usernameFromToken = getUsernameFromToken(token);
        return (usernameFromToken.equals(userDetails.getUsername())
                && isTokenNotExpired(token)
                && !isMfaPending(token));
    }

    /**
     * True when the token is only a 2FA challenge. Such a token proves the
     * password was correct and nothing more — it must not authenticate a
     * request anywhere.
     */
    public boolean isMfaPending(String token){
        return Boolean.TRUE.equals(getAllClaimsFromToken(token).get(MFA_PENDING_CLAIM, Boolean.class));
    }

    //Token Generation

    private String buildToken(Map<String, Object> extraClaims, LoginRequest loginRequest){
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(loginRequest.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String generateToken(Map<String, Object> claims, LoginRequest loginRequest){
        return buildToken(claims, loginRequest);
    }

    /**
     * Short-lived token issued after a correct password when the account has
     * 2FA enabled. It carries {@link #MFA_PENDING_CLAIM}, so it authenticates
     * nothing; the holder must exchange it via /verify-2fa-login.
     */
    public String generateMfaChallengeToken(String username){
        return Jwts.builder()
                .subject(username)
                .claim("username", username)
                .claim(MFA_PENDING_CLAIM, true)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + MFA_CHALLENGE_TTL_MILLIS))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String generateTokenFromUsername(UserDetailImpl userDetails) {
        String username = userDetails.getUsername();
        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                .toList();

        return Jwts.builder()
                .subject(username)
                .claim("username", username)
                // Downstream services scope user-owned rows by userId, not by
                // the subject (which is the username) — so it has to be here.
                .claim("userId", userDetails.getUserId())
                .claim("roles", roles)
                .claim("is2faEnabled", userDetails.is2faEnabled())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    // inside JwtService
    public List<String> getRolesFromToken(String token) {
        Object rolesObj = getAllClaimsFromToken(token).get("roles"); // uses your private getAllClaimsFromToken

        if (rolesObj == null) return List.of();

        if (rolesObj instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }

        // if stored as "ROLE_ADMIN,ROLE_CUSTOMER"
        String rolesStr = String.valueOf(rolesObj);
        if (rolesStr.isBlank()) return List.of();
        return Arrays.stream(rolesStr.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .toList();
    }

    public String getRefKeyFromToken(String token) {
        return getUsernameFromToken(token);
    }


    public SecretKey getSigningKey(){
        byte[] decode = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(decode);
    }

}
