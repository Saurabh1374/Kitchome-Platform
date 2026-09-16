package com.kitchome.auth.service;

import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.entity.RefreshToken;
import com.kitchome.auth.entity.User;
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
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final UserRepositoryDao userRepositoryDao;

    /**
     * Finalizes the login process by generating tokens, capturing metadata,
     * and setting HttpOnly cookies for both Access and Refresh tokens.
     */
    public String finalizeLogin(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        String username = authentication.getName();
        List<String> authRoles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        log.info("Finalizing login for user: {} with authorities: {}", username, authRoles);

        Optional<User> userOpt = userRepositoryDao.findUserByUsernameIgnoreCase(username)
                .or(() -> userRepositoryDao.findUserByEmailIgnoreCase(username));
        String canonicalUsername = userOpt.map(User::getUsername).orElse(username);
        String email = userOpt.map(User::getEmail).orElse(null);
        String tenantId = userOpt.map(u -> u.getOrganization() != null ? u.getOrganization().getCode() : "default").orElse("default");
        String tier = userOpt.map(User::getTier).orElse("free");
        List<String> roles = userOpt.map(u -> u.getRoles().stream().map(r -> r.getRole()).collect(Collectors.toList()))
                .orElse(authRoles);

        // 1. Generate Enriched Minimal Access Token (JWT) with tenant_id and tier
        String accessToken = jwtUtil.generateToken(canonicalUsername, email, tenantId, tier, roles);

        // 2. Capture Metadata & Generate Refresh Token
        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String fingerprint = generateFingerprint(ip, userAgent);

        RefreshToken refreshToken = refreshTokenService.generateAndStoreRefreshToken(canonicalUsername, fingerprint, ip,
                userAgent);

        // 3. Set Cookies
        ResponseCookie jwtCookie = ResponseCookie.from("kitchome_access", accessToken)
                .httpOnly(true)
                .secure(false) // TODO: Set to true in production (HTTPS)
                .path("/")
                .maxAge(3600) // 1 hour
                .sameSite("Lax")
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken.getToken())
                .httpOnly(true)
                .secure(false) // TODO: Set to true in production
                .path("/")
                .maxAge(15 * 24 * 60 * 60) // 15 days
                .sameSite("Lax")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        response.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);

        return accessToken;
    }

    private String generateFingerprint(String ip, String userAgent) {
        return UUID.nameUUIDFromBytes(((userAgent != null ? userAgent : "") + (ip != null ? ip : "")).getBytes()).toString();
    }

    /**
     * Clears authentication cookies to log out the user.
     */
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        ResponseCookie jwtCookie = ResponseCookie.from("kitchome_access", "")
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
