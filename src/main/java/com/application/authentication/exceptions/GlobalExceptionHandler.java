package com.application.authentication.exceptions;

import com.application.authentication.utils.ApiResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Messages safe to hand back to a caller. Anything else — Feign transport
     * errors carrying internal service URLs, JPA/SQL text, class names — is
     * logged and replaced with a generic string, since those details map out
     * the internals for an attacker.
     */
    private static final Set<String> SAFE_MESSAGES = Set.of(
            "Username already exists",
            "Email already exists",
            "User not found",
            "Account is disabled",
            "Account is locked",
            "Account is expired",
            "Credentials expired",
            "Unauthorized",
            "Invalid delegate bootstrap key",
            "Delegate already exists. Private delegate signup is disabled.",
            "You already have a pending request for admin role",
            "Request not found",
            "Already processed"
    );

    public ResponseEntity<ApiResponse> getResponse(String message, int statusCode) {
        return new ResponseEntity<>(ApiResponse.builder().status("FAILED").message(message).build(), HttpStatusCode.valueOf(statusCode));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException ex) {
        String message = ex.getMessage();
        if (message == null || !SAFE_MESSAGES.contains(message)) {
            log.error("unhandled runtime exception", ex);
            message = "Request could not be completed";
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("error", "Bad Request");
        body.put("message", message);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse> handleSecurityException(Exception exception) {
        ResponseEntity<ApiResponse> response = null;

        if (exception instanceof BadCredentialsException) {
            return getResponse(exception.getMessage(), 401);
        }

        if (exception instanceof AccountStatusException) {
            return getResponse("The account is locked or disabled", 401);
        }

        if (exception instanceof AccessDeniedException) {
            return getResponse("You are not authorized to access this resource", 403);
        }

        if (exception instanceof SignatureException) {
            return getResponse("Signature is invalid", 403);
        }
        return getResponse("Something went wrong", 500);
    }

    @ExceptionHandler(ClientConnectException.class)
    public ResponseEntity<ApiResponse> handleClientConnectException(ClientConnectException ex) {
        return new ResponseEntity<>(
                new ApiResponse("FAILED", null, ex.getMessage()),
                HttpStatus.BAD_GATEWAY
        );
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<?> handleDuplicate(DataIntegrityViolationException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of(
                        "status", 409,
                        "message", "Username or email already exists"
                ));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(AccessDeniedException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", LocalDateTime.now().toString());
        body.put("status", 403);
        body.put("error", "Forbidden");
        body.put("message", "Permission Denied! Only Delegate user have access to these resources");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<Map<String, Object>> handleExpiredJwtException(ExpiredJwtException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", LocalDateTime.now().toString());
        body.put("status", 401);
        body.put("error", "TOKEN_EXPIRED");
        body.put("message", "Session has expired. Please login again.");

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

}
