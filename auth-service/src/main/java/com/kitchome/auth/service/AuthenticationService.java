package com.kitchome.auth.service;

import com.kitchome.auth.authentication.CustomUserDetails;
import com.kitchome.auth.entity.RefreshToken;
import com.kitchome.auth.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    /**
     * Finalizes the login process by generating tokens, capturing metadata,
     * and setting HttpOnly cookies for both Access and Refresh tokens.
     */
    public String finalizeLogin(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        log.info("Finalizing login for user: {} with roles: {}", username, roles);

        // 1. Generate Enriched Access Token (JWT)
        // We can extend JwtUtil to include roles if needed, currently it supports
        // agentId and scopes.
        // For now, let's use the existing generateToken and we might enhance it later.
        String accessToken = jwtUtil.generateToken(username);

        // 2. Capture Metadata & Generate Refresh Token
        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String fingerprint = generateFingerprint(ip, userAgent);

        RefreshToken refreshToken = refreshTokenService.generateAndStoreRefreshToken(username, fingerprint, ip,
                userAgent);

        // 3. Set Cookies

        // Access Token Cookie (Short lived, e.g., same as JWT expiration)
        ResponseCookie jwtCookie = ResponseCookie.from("jwt", accessToken)
                .httpOnly(true)
                .secure(false) // TODO: Set to true in production (HTTPS)
                .path("/")
                .maxAge(3600) // 1 hour
                .sameSite("Lax")
                .build();

        // Refresh Token Cookie (Long lived)
        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken.getToken())
                .httpOnly(true)
                .secure(false) // TODO: Set to true in production
                .path("/")
                .maxAge(15 * 24 * 60 * 60) // 15 days
                .sameSite("Lax")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        // Also add Authorization header for immediate response visibility if needed
        response.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);

        return accessToken;
    }

    private String generateFingerprint(String ip, String userAgent) {
        return UUID.nameUUIDFromBytes((userAgent + ip).getBytes()).toString();
    }

    /**
     * Clears authentication cookies to log out the user.
     */
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        ResponseCookie jwtCookie = ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .sameSite("Strict")
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .sameSite("Strict")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        log.info("Authentication cookies cleared successfully.");
    }
}
