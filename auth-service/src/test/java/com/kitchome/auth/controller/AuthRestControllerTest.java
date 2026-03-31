package com.kitchome.auth.controller;

import com.kitchome.auth.Exception.AuthException;
import com.kitchome.auth.authentication.UserCredentials;
import com.kitchome.auth.entity.RefreshToken;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.payload.*;
import com.kitchome.auth.service.AuthenticationService;
import com.kitchome.auth.service.ForgotPasswordService;
import com.kitchome.auth.service.RefreshTokenService;
import com.kitchome.auth.service.ThirdPartyIntegrationService;
import com.kitchome.auth.util.ErrorCode;
import com.kitchome.auth.util.JwtUtil;
import com.kitchome.common.payload.ApiResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthRestControllerTest {

    @Mock
    private UserCredentials userService;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private ForgotPasswordService forgotPasswordService;
    @Mock
    private ThirdPartyIntegrationService integrationService;
    @Mock
    private AuthenticationService authService;

    @Mock
    private Authentication authentication;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @InjectMocks
    private AuthRestController controller;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();
    }

    @Test
    void testRegisterUser() {
        RegisterUserDTO dto = new RegisterUserDTO();
        ResponseEntity<ApiResponse<String>> res = controller.createUser(dto);
        assertEquals(HttpStatus.CREATED, res.getStatusCode());
        verify(userService).registerUser(dto);
    }

    @Test
    void testLoginSuccess() {
        AuthRequestDTO req = new AuthRequestDTO();
        req.setUsername("user");
        req.setPassword("pass");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(authService.finalizeLogin(request, response, authentication)).thenReturn("accessToken");

        ResponseEntity<ApiResponse<JwtResponseDTO>> res = controller.login(req, request, response);
        assertEquals(HttpStatus.OK, res.getStatusCode());
        assertEquals("accessToken", res.getBody().getPayload().getAccessToken());
    }

    @Test
    void testLoginDisabled() {
        AuthRequestDTO req = new AuthRequestDTO();
        when(authenticationManager.authenticate(any())).thenThrow(new DisabledException("disabled"));

        ResponseEntity<ApiResponse<JwtResponseDTO>> res = controller.login(req, request, response);
        assertEquals(HttpStatus.FORBIDDEN, res.getStatusCode());
    }

    @Test
    void testLoginBadCredentials() {
        AuthRequestDTO req = new AuthRequestDTO();
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));

        ResponseEntity<ApiResponse<JwtResponseDTO>> res = controller.login(req, request, response);
        assertEquals(HttpStatus.UNAUTHORIZED, res.getStatusCode());
    }

    @Test
    void testAgentLogin() {
        AuthRequestDTO req = new AuthRequestDTO();
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(authService.finalizeLogin(request, response, authentication)).thenReturn("agentToken");

        ResponseEntity<ApiResponse<JwtResponseDTO>> res = controller.agentLogin(req, request, response);
        assertEquals(HttpStatus.OK, res.getStatusCode());
        assertEquals("agentToken", res.getBody().getPayload().getAccessToken());
    }

    @Test
    void testRefreshTokenSuccess() {
        // Do NOT send X-Device-Fingerprint header so the fallback (IP+UserAgent) is used,
        // matching the strategy used at login time in AuthenticationService.generateFingerprint().
        request.setCookies(new jakarta.servlet.http.Cookie("refreshToken", "rtoken"));
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("User-Agent", "agent");

        // Compute the expected fingerprint the same way getFingerprint() fallback does
        String expectedFp = java.util.UUID.nameUUIDFromBytes(("agent" + "127.0.0.1").getBytes()).toString();

        RefreshToken token = new RefreshToken();
        token.setFingerprint(expectedFp);
        token.setIp("127.0.0.1");
        User user = new User();
        user.setUsername("user");
        token.setUser(user);

        when(refreshTokenService.validate("rtoken")).thenReturn(token);
        when(jwtUtil.generateToken("user")).thenReturn("newAccess");

        RefreshToken newRefresh = new RefreshToken();
        newRefresh.setToken("newRefresh");
        when(refreshTokenService.generateAndStoreRefreshToken("user", expectedFp, "127.0.0.1", "agent")).thenReturn(newRefresh);

        ResponseEntity<ApiResponse<JwtResponseDTO>> res = controller.refreshToken(request, response);
        assertEquals(HttpStatus.OK, res.getStatusCode());
        assertTrue(res.getHeaders().containsKey(HttpHeaders.AUTHORIZATION));
        verify(refreshTokenService).invalidate(token);
    }

    @Test
    void testRefreshTokenNotFound() {
        AuthException ex = assertThrows(AuthException.class, () -> controller.refreshToken(request, response));
        assertEquals(ErrorCode.TOKEN_NOT_FOUND.getErrorCode(), ex.getErrorCode());
    }

    @Test
    void testRefreshTokenSuspicious() {
        request.setCookies(new jakarta.servlet.http.Cookie("refreshToken", "rtoken"));
        request.addHeader("X-Device-Fingerprint", "fp");
        request.setRemoteAddr("127.0.0.1");

        RefreshToken token = new RefreshToken();
        token.setFingerprint("otherFp");
        token.setIp("127.0.0.1");

        when(refreshTokenService.validate("rtoken")).thenReturn(token);

        AuthException ex = assertThrows(AuthException.class, () -> controller.refreshToken(request, response));
        assertEquals(ErrorCode.SUSPESIOUS.getErrorCode(), ex.getErrorCode());
    }

    @Test
    void testGetCurrentUserUnauthenticated() {
        ResponseEntity<ApiResponse<UserProfileDTO>> res = controller.getCurrentUser();
        assertEquals(HttpStatus.UNAUTHORIZED, res.getStatusCode());
    }

    @Test
    void testGetCurrentUserSuccess() {
        SecurityContext ctx = mock(SecurityContext.class);
        SecurityContextHolder.setContext(ctx);
        when(ctx.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("user");

        GrantedAuthority currentAuthority = mock(GrantedAuthority.class);
        when(currentAuthority.getAuthority()).thenReturn("ROLE_USER");
        doReturn(Collections.singletonList(currentAuthority)).when(authentication).getAuthorities();

        ResponseEntity<ApiResponse<UserProfileDTO>> res = controller.getCurrentUser();
        assertEquals(HttpStatus.OK, res.getStatusCode());
        assertEquals("user", res.getBody().getPayload().getUsername());
        assertEquals("ROLE_USER", res.getBody().getPayload().getRoles());
    }

    @Test
    void testVerifyEmailSuccess() {
        ResponseEntity<?> res = controller.verifyEmail("token");
        assertEquals(HttpStatus.FOUND, res.getStatusCode());
        assertEquals("/login?verified=true", res.getHeaders().getLocation().toString());
    }

    @Test
    void testVerifyEmailAlreadyVerified() {
        doThrow(new AuthException(ErrorCode.TOKEN_NOT_FOUND)).when(userService).verifyUser("token");
        ResponseEntity<?> res = controller.verifyEmail("token");
        assertEquals(HttpStatus.FOUND, res.getStatusCode());
        assertEquals("/login?alreadyVerified=true", res.getHeaders().getLocation().toString());
    }

    @Test
    void testVerifyEmailOtherException() {
        doThrow(new AuthException(ErrorCode.INTERNAL_SERVER_ERROR)).when(userService).verifyUser("token");
        assertThrows(AuthException.class, () -> controller.verifyEmail("token"));
    }

    @Test
    void testResendVerificationSuccess() {
        ResponseEntity<ApiResponse<String>> res = controller.resendVerification(Map.of("email", "test@test.com"));
        assertEquals(HttpStatus.OK, res.getStatusCode());
        verify(userService).resendVerificationLink("test@test.com");
    }

    @Test
    void testResendVerificationAlreadyVerified() {
        doThrow(new AuthException(ErrorCode.INTERNAL_SERVER_ERROR, "Account is already verified")).when(userService).resendVerificationLink("test@test.com");
        ResponseEntity<ApiResponse<String>> res = controller.resendVerification(Map.of("email", "test@test.com"));
        assertEquals(HttpStatus.OK, res.getStatusCode());
        assertEquals("ALREADY_VERIFIED", res.getBody().getPayload());
    }

    @Test
    void testForgotPassword() {
        ResponseEntity<ApiResponse<String>> res = controller.forgotPassword(Map.of("email", "test@test.com"));
        assertEquals(HttpStatus.OK, res.getStatusCode());
        verify(forgotPasswordService).processForgotPassword("test@test.com");
    }

    @Test
    void testResetPassword() {
        User user = new User();
        when(forgotPasswordService.getUserByToken("token")).thenReturn(user);

        ResponseEntity<ApiResponse<String>> res = controller.resetPassword(Map.of("token", "token", "newPassword", "pass"));
        assertEquals(HttpStatus.OK, res.getStatusCode());

        verify(forgotPasswordService).validateToken("token");
        verify(userService).updatePassword(user, "pass");
        verify(forgotPasswordService).deleteToken("token");
    }

    @Test
    void testLinkIntegration() {
        when(authentication.getName()).thenReturn("user");
        IntegrationLinkRequest req = new IntegrationLinkRequest();
        req.setCode("code");
        req.setRedirectUri("uri");

        when(integrationService.linkUserToProvider("user", "google", "code", "uri")).thenReturn(Mono.empty());

        Mono<ResponseEntity<ApiResponse<String>>> res = controller.linkIntegration("google", req, authentication);
        ResponseEntity<ApiResponse<String>> responseEntity = res.block();
        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }

    @Test
    void testGetIntegrationKey() {
        when(authentication.getName()).thenReturn("user");
        when(integrationService.getSignedAccessKey("user", "google")).thenReturn(Mono.just("signedKey"));

        Mono<ResponseEntity<ApiResponse<String>>> res = controller.getIntegrationKey("google", authentication);
        ResponseEntity<ApiResponse<String>> responseEntity = res.block();
        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals("signedKey", responseEntity.getBody().getPayload());
    }

    @Test
    void testAuthorizeIntegration() {
        when(authentication.getName()).thenReturn("user");
        when(integrationService.getAuthorizationLink("google", "user")).thenReturn("link");

        ResponseEntity<ApiResponse<Map<String, String>>> res = controller.authorizeIntegration("google", authentication);
        assertEquals(HttpStatus.OK, res.getStatusCode());
        assertEquals("link", res.getBody().getPayload().get("authorizationUrl"));
    }

    @Test
    void testOauth2Callback() {
        when(integrationService.linkUserToProvider(eq("stateUser"), eq("google"), eq("code"), anyString())).thenReturn(Mono.empty());
        Mono<ResponseEntity<ApiResponse<String>>> res = controller.oauth2Callback("google", "code", "stateUser");

        ResponseEntity<ApiResponse<String>> responseEntity = res.block();
        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }

    @Test
    void testGetIntegrationsUnauthenticated() {
        ResponseEntity<ApiResponse<List<IntegrationInfoDTO>>> res = controller.getIntegrations(null);
        assertEquals(HttpStatus.UNAUTHORIZED, res.getStatusCode());
    }

    @Test
    void testGetIntegrationsSuccess() {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("user");
        when(integrationService.getAvailableIntegrations("user")).thenReturn(Collections.emptyList());

        ResponseEntity<ApiResponse<List<IntegrationInfoDTO>>> res = controller.getIntegrations(authentication);
        assertEquals(HttpStatus.OK, res.getStatusCode());
    }
}
