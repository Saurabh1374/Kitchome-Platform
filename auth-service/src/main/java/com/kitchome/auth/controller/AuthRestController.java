package com.kitchome.auth.controller;

import com.kitchome.auth.Exception.AuthException;
import com.kitchome.auth.authentication.UserCredentials;
import com.kitchome.auth.entity.RefreshToken;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.payload.AuthRequestDTO;
import com.kitchome.auth.payload.IntegrationInfoDTO;
import com.kitchome.auth.payload.JwtResponseDTO;
import com.kitchome.auth.payload.RegisterUserDTO;
import com.kitchome.auth.payload.UserProfileDTO;
import com.kitchome.auth.payload.IntegrationLinkRequest;
import com.kitchome.auth.service.RefreshTokenService;
import com.kitchome.auth.util.ErrorCode;
import com.kitchome.auth.util.JwtUtil;
import com.kitchome.common.payload.ApiResponse;
import com.kitchome.auth.payload.IntegrationInfoDTO;
import java.util.List;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthRestController {

    private final UserCredentials userService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final com.kitchome.auth.service.ForgotPasswordService forgotPasswordService;
    private final com.kitchome.auth.service.ThirdPartyIntegrationService integrationService;
    private final com.kitchome.auth.service.AuthenticationService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<String>> createUser(@RequestBody @Valid RegisterUserDTO userDto) {
        userService.registerUser(userDto);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.<String>success(
                        "Registration successful. Please check your email for the verification link.",
                        "Registration initiated"));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<JwtResponseDTO>> login(@RequestBody AuthRequestDTO request,
            HttpServletRequest httpRequest, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

            String accessToken = authService.finalizeLogin(httpRequest, response, authentication);

            return ResponseEntity.status(HttpStatus.OK)
                    .body(ApiResponse.<JwtResponseDTO>success(new JwtResponseDTO(accessToken, null)));
        } catch (org.springframework.security.authentication.DisabledException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(ApiResponse.<JwtResponseDTO>error("Account disabled. Please verify your email.", "DISABLED",
                            HttpStatus.FORBIDDEN));
        } catch (org.springframework.security.authentication.BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.<JwtResponseDTO>error("Invalid username or password", "UNAUTHORIZED",
                            HttpStatus.UNAUTHORIZED));
        }
    }

    @PostMapping("/agent/login")
    public ResponseEntity<ApiResponse<JwtResponseDTO>> agentLogin(@RequestBody AuthRequestDTO request,
            HttpServletRequest httpRequest, HttpServletResponse response) {
        // For simplicity, agents login with username/password too, but get an agent_id
        // claim
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        String accessToken = authService.finalizeLogin(httpRequest, response, authentication);

        return ResponseEntity.ok(ApiResponse.<JwtResponseDTO>success(new JwtResponseDTO(accessToken, null)));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<JwtResponseDTO>> refreshToken(HttpServletRequest httpRequest,
            HttpServletResponse response) {
        try {
            String rawToken = Arrays.stream(Optional.ofNullable(httpRequest.getCookies()).orElse(new Cookie[0]))
                    .filter(c -> "refreshToken".equals(c.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElseThrow(() -> new AuthException(ErrorCode.TOKEN_NOT_FOUND));
            String fingerprint = getFingerprint(httpRequest);
            String ip = httpRequest.getRemoteAddr();

            RefreshToken token = refreshTokenService.validate(rawToken);

            // Optional: verify fingerprint/ip/userAgent matches
            if (!token.getFingerprint().equals(fingerprint) || !token.getIp().equals(ip)) {
                throw new AuthException(ErrorCode.SUSPESIOUS);
            }

            refreshTokenService.invalidate(token); // rotation

            User user = token.getUser();
            String newAccessToken = jwtUtil.generateToken(user.getUsername());
            RefreshToken newRefresh = refreshTokenService
                    .generateAndStoreRefreshToken(user.getUsername(), fingerprint, ip,
                            httpRequest.getHeader("User-Agent"));

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + newAccessToken);

            ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", newRefresh.getToken())
                    .httpOnly(true)
                    .secure(false) // TODO: Set to true in production
                    .path("/")
                    .maxAge(15 * 24 * 60 * 60)
                    .sameSite("Strict")
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

            return ResponseEntity.status(HttpStatus.OK).headers(headers)
                    .body(ApiResponse
                            .<JwtResponseDTO>success(new JwtResponseDTO(newAccessToken, newRefresh.getToken())));
        } catch (AuthException ae) {
            log.error("Failed request", ae);
            throw ae;
        }
    }

    private String getFingerprint(HttpServletRequest request) {
        // Prefer header or cookie
        String fingerprint = request.getHeader("X-Device-Fingerprint");
        if (fingerprint == null) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie c : cookies) {
                    if ("fingerprint".equals(c.getName())) {
                        return c.getValue();
                    }
                }
            }
        }
        return "unknown";
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserProfileDTO>> getCurrentUser() {
        Authentication authentication = org.springframework.security.core.context.SecurityContextHolder.getContext()
                .getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() ||
                authentication instanceof org.springframework.security.authentication.AnonymousAuthenticationToken) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String username = authentication.getName();
        String roles = authentication.getAuthorities().stream()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .collect(java.util.stream.Collectors.joining(", "));

        return ResponseEntity.ok(ApiResponse.<UserProfileDTO>success(new UserProfileDTO(username, roles)));
    }

    @GetMapping("/verify-email")
    public ResponseEntity<ApiResponse<String>> verifyEmail(@RequestParam String token) {
        userService.verifyUser(token);
        return ResponseEntity.ok(ApiResponse.<String>success("Email verified successfully. You can now login."));
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<String>> resendVerification(@RequestBody java.util.Map<String, String> payload) {
        String email = payload.get("email");
        userService.resendVerificationLink(email);
        return ResponseEntity.ok(ApiResponse.<String>success("A new verification link has been sent to your email."));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(@RequestBody java.util.Map<String, String> payload) {
        String email = payload.get("email");
        forgotPasswordService.processForgotPassword(email);
        return ResponseEntity
                .ok(ApiResponse
                        .<String>success("If an account exists with that email, a password reset link has been sent."));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(@RequestBody java.util.Map<String, String> payload) {
        String token = payload.get("token");
        String newPassword = payload.get("newPassword");

        forgotPasswordService.validateToken(token);
        User user = forgotPasswordService.getUserByToken(token);
        userService.updatePassword(user, newPassword);
        forgotPasswordService.deleteToken(token);
        return ResponseEntity.ok(ApiResponse.<String>success("Password reset successfully. You can now login."));
    }

    @PostMapping("/integrations/{name}/link")
    public Mono<ResponseEntity<ApiResponse<String>>> linkIntegration(@PathVariable String name,
            @RequestBody IntegrationLinkRequest request, Authentication auth) {
        return integrationService.linkUserToProvider(auth.getName(), name, request.getCode(), request.getRedirectUri())
                .thenReturn(ResponseEntity.ok(ApiResponse.success("Successfully linked " + name)));
    }

    @GetMapping("/integrations/{name}/key")
    public Mono<ResponseEntity<ApiResponse<String>>> getIntegrationKey(@PathVariable String name, Authentication auth) {
        return integrationService.getSignedAccessKey(auth.getName(), name)
                .map(signedKey -> ResponseEntity.ok(ApiResponse.success(signedKey)));
    }

    @GetMapping("/integrations/{name}/authorize")
    public ResponseEntity<ApiResponse<java.util.Map<String, String>>> authorizeIntegration(@PathVariable String name,
            Authentication auth) {
        String authUrl = integrationService.getAuthorizationLink(name, auth.getName());
        return ResponseEntity.ok(ApiResponse.success(java.util.Map.of("authorizationUrl", authUrl)));
    }

    @GetMapping("/integrations/{name}/callback")
    public Mono<ResponseEntity<ApiResponse<String>>> oauth2Callback(@PathVariable String name,
            @RequestParam String code, @RequestParam String state) {
        // 'state' here is the username we passed
        return integrationService.linkUserToProvider(state, name, code,
                String.format("http://localhost:8080/api/v1/auth/integrations/%s/callback", name))
                .thenReturn(ResponseEntity
                        .ok(ApiResponse.success("Successfully linked " + name + ". You can now close this window.")));
    }

    @GetMapping("/integrations")
    public ResponseEntity<ApiResponse<List<IntegrationInfoDTO>>> getIntegrations(Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(integrationService.getAvailableIntegrations(auth.getName())));
    }


}
