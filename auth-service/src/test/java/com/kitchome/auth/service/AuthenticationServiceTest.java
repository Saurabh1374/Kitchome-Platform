package com.kitchome.auth.service;

import com.kitchome.auth.entity.RefreshToken;
import com.kitchome.auth.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private AuthenticationService authenticationService;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void testFinalizeLogin() {
        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn("testuser");

        Collection authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        when(auth.getAuthorities()).thenReturn(authorities);

        request.setRemoteAddr("127.0.0.1");
        request.addHeader("User-Agent", "Mozilla");

        when(jwtUtil.generateToken("testuser")).thenReturn("mock-jwt-token");

        RefreshToken mockRefreshToken = new RefreshToken();
        mockRefreshToken.setToken("mock-refresh-token");
        
        when(refreshTokenService.generateAndStoreRefreshToken(
                eq("testuser"), anyString(), eq("127.0.0.1"), eq("Mozilla")
        )).thenReturn(mockRefreshToken);

        String result = authenticationService.finalizeLogin(request, response, auth);

        assertEquals("mock-jwt-token", result);

        List<String> setCookies = response.getHeaders(HttpHeaders.SET_COOKIE);
        assertNotNull(setCookies);
        assertEquals(2, setCookies.size());

        boolean hasJwtCookie = setCookies.stream().anyMatch(c -> c.contains("kitchome_access=mock-jwt-token") && c.contains("HttpOnly") && c.contains("Max-Age=3600"));
        boolean hasRefreshCookie = setCookies.stream().anyMatch(c -> c.contains("refreshToken=mock-refresh-token") && c.contains("HttpOnly") && c.contains("Max-Age=1296000"));

        assertTrue(hasJwtCookie);
        assertTrue(hasRefreshCookie);

        String authHeader = response.getHeader(HttpHeaders.AUTHORIZATION);
        assertEquals("Bearer mock-jwt-token", authHeader);
    }

    @Test
    void testLogout() {
        authenticationService.logout(request, response);

        List<String> setCookies = response.getHeaders(HttpHeaders.SET_COOKIE);
        assertNotNull(setCookies);
        assertEquals(2, setCookies.size());

        boolean hasJwtCookie = setCookies.stream().anyMatch(c -> c.contains("kitchome_access=") && c.contains("Max-Age=0") && c.contains("SameSite=Strict"));
        boolean hasRefreshCookie = setCookies.stream().anyMatch(c -> c.contains("refreshToken=") && c.contains("Max-Age=0") && c.contains("SameSite=Strict"));

        assertTrue(hasJwtCookie);
        assertTrue(hasRefreshCookie);
    }
}
