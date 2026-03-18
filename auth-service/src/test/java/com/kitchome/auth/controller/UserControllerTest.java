package com.kitchome.auth.controller;

import com.kitchome.auth.Exception.AuthException;
import com.kitchome.auth.authentication.CustomUserDetails;
import com.kitchome.auth.authentication.UserCredentials;
import com.kitchome.auth.entity.RefreshToken;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.payload.AuthRequestDTO;
import com.kitchome.auth.payload.JwtResponseDTO;
import com.kitchome.auth.payload.RegisterUserDTO;
import com.kitchome.auth.service.RefreshTokenService;
import com.kitchome.auth.util.ErrorCode;
import com.kitchome.auth.util.JwtUtil;
import org.apache.coyote.BadRequestException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import jakarta.servlet.http.Cookie;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private UserCredentials userService;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private AuthenticationSuccessHandler successHandler;
    @Mock
    private Authentication authentication;

    @InjectMocks
    private UserController controller;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();
    }

    @Test
    void testShowRegistrationForm() {
        assertEquals("register", controller.showRegistrationForm());
    }

    @Test
    void testLoginPage() {
        assertEquals("login", controller.loginPage());
    }

    @Test
    void testCreateUserSuccess() {
        RegisterUserDTO dto = new RegisterUserDTO();
        when(userService.registerUser(any())).thenReturn(true);
        ResponseEntity<?> res = controller.createUser(dto);
        assertEquals(HttpStatus.CREATED, res.getStatusCode());
        assertEquals("User registered successfully", res.getBody());
    }

    @Test
    void testCreateUserException() {
        RegisterUserDTO dto = new RegisterUserDTO();
        when(userService.registerUser(any())).thenThrow(new RuntimeException("Error"));
        AuthException ex = assertThrows(AuthException.class, () -> controller.createUser(dto));
        assertEquals(ErrorCode.USER_ALREADY_AVAILABLE.getErrorCode(), ex.getErrorCode());
    }

    @Test
    void testLoginSuccess() {
        AuthRequestDTO req = new AuthRequestDTO();
        req.setUsername("user");
        req.setPassword("pass");

        UserDetails userDetails = mock(UserDetails.class);
        when(userDetails.getUsername()).thenReturn("user");
        
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(jwtUtil.generateToken("user")).thenReturn("access");

        RefreshToken token = new RefreshToken();
        token.setToken("rtoken");
        when(refreshTokenService.generateAndStoreRefreshToken(eq("user"), anyString(), anyString(), any())).thenReturn(token);

        ResponseEntity<?> res = controller.login(req, request, response);
        
        assertEquals(HttpStatus.OK, res.getStatusCode());
        assertTrue(res.getHeaders().containsKey(HttpHeaders.AUTHORIZATION));
        assertTrue(response.containsHeader(HttpHeaders.SET_COOKIE));
        
        JwtResponseDTO body = (JwtResponseDTO) res.getBody();
        assertEquals("access", body.getAccessToken());
        assertEquals("rtoken", body.getRefreshToken());
    }

    @Test
    void testRefreshTokenSuccess() {
        request.setCookies(new Cookie("refreshToken", "rtoken"));
        request.addHeader("X-Device-Fingerprint", "fp");
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("User-Agent", "agent");

        RefreshToken token = new RefreshToken();
        token.setFingerprint("unknown");
        token.setIp("127.0.0.1");
        User user = new User();
        user.setUsername("user");
        token.setUser(user);

        when(refreshTokenService.validate("rtoken")).thenReturn(token);
        when(jwtUtil.generateToken("user")).thenReturn("newAccess");

        RefreshToken newRefresh = new RefreshToken();
        newRefresh.setToken("newRefresh");
        when(refreshTokenService.generateAndStoreRefreshToken("user", "unknown", "127.0.0.1", "agent")).thenReturn(newRefresh);

        ResponseEntity<JwtResponseDTO> res = controller.refreshToken(request, response);
        
        assertEquals(HttpStatus.OK, res.getStatusCode());
        assertTrue(res.getHeaders().containsKey(HttpHeaders.AUTHORIZATION));
        verify(refreshTokenService).invalidate(token);
        
        JwtResponseDTO body = res.getBody();
        assertEquals("newAccess", body.getAccessToken());
        assertEquals("newRefresh", body.getRefreshToken());
    }

    @Test
    void testRefreshTokenNotFound() {
        AuthException ex = assertThrows(AuthException.class, () -> controller.refreshToken(request, response));
        assertEquals(ErrorCode.INTERNAL_SERVER_ERROR.getErrorCode(), ex.getErrorCode());
        assertTrue(ex.getCause() instanceof AuthException);
        assertEquals(ErrorCode.TOKEN_NOT_FOUND.getErrorCode(), ((AuthException) ex.getCause()).getErrorCode());
    }

    @Test
    void testRefreshTokenSuspicious() {
        request.setCookies(new Cookie("refreshToken", "rtoken"));
        request.addHeader("X-Device-Fingerprint", "fp");
        request.setRemoteAddr("127.0.0.1");

        RefreshToken token = new RefreshToken();
        token.setFingerprint("otherFp");
        token.setIp("127.0.0.1");

        when(refreshTokenService.validate("rtoken")).thenReturn(token);

        AuthException ex = assertThrows(AuthException.class, () -> controller.refreshToken(request, response));
        assertEquals(ErrorCode.INTERNAL_SERVER_ERROR.getErrorCode(), ex.getErrorCode());
        assertTrue(ex.getCause() instanceof AuthException);
        assertEquals(ErrorCode.SUSPESIOUS.getErrorCode(), ((AuthException) ex.getCause()).getErrorCode());
    }

    @Test
    void testDashboardSuccess() throws Exception {
        CustomUserDetails userDetails = mock(CustomUserDetails.class);
        when(userDetails.getPassword()).thenReturn("pass");
        
        GrantedAuthority auth = new SimpleGrantedAuthority("ROLE_USER");
        doReturn(Collections.singletonList(auth)).when(authentication).getAuthorities();
        when(authentication.getName()).thenReturn("user");
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userDetails);

        SecurityContext ctx = mock(SecurityContext.class);
        when(ctx.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(ctx);

        Model model = new ConcurrentModel();
        String view = controller.dashboard(model);
        
        assertEquals("dashboard", view);
        assertEquals("user", model.getAttribute("username"));
        assertEquals("ROLE_USER", model.getAttribute("role"));
        assertEquals("pass", model.getAttribute("pass"));
        assertNotNull(model.getAttribute("today"));
    }

    @Test
    void testDashboardUnauthenticated() {
        SecurityContext ctx = mock(SecurityContext.class);
        when(ctx.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(ctx);

        Model model = new ConcurrentModel();
        assertThrows(BadRequestException.class, () -> controller.dashboard(model));
    }

    @Test
    void testDashboardAnonymous() {
        AnonymousAuthenticationToken anonAuth = mock(AnonymousAuthenticationToken.class);
        when(anonAuth.isAuthenticated()).thenReturn(true);
        
        SecurityContext ctx = mock(SecurityContext.class);
        when(ctx.getAuthentication()).thenReturn(anonAuth);
        SecurityContextHolder.setContext(ctx);

        Model model = new ConcurrentModel();
        assertThrows(BadRequestException.class, () -> controller.dashboard(model));
    }
}
