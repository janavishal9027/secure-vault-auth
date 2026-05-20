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
        return (usernameFromToken.equals(loginRequest.getUsername()) && isTokenNotExpired(token));
    }

    private boolean isTokenNotExpired(String token){
        return !extractExpiration(token).before(new Date());
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        String usernameFromToken = getUsernameFromToken(token);
        return (usernameFromToken.equals(userDetails.getUsername()) && isTokenNotExpired(token));
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
