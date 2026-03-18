package com.kitchome.auth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    @InjectMocks
    private JwtUtil jwtUtil;

    @Mock
    private UserDetails userDetails;

    private final String SECRET = "mytestsecretkeywhichisverylongandsecureenoughformocking1234567890="; // Base64 arbitrary secret
    private final long EXPIRATION_MS = 1000 * 60 * 60; // 1 hour

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtUtil, "SECRET", SECRET);
        ReflectionTestUtils.setField(jwtUtil, "expieryDuration", EXPIRATION_MS);
    }

    @Test
    void testGenerateAndExtractUsername() {
        String token = jwtUtil.generateToken("testuser");
        assertNotNull(token);
        assertEquals("testuser", jwtUtil.extractUsername(token));
    }

    @Test
    void testGenerateTokenWithClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "ADMIN");

        String token = jwtUtil.GenerateTokenWithClaims(claims, "adminuser");
        assertNotNull(token);
        assertEquals("adminuser", jwtUtil.extractUsername(token));

        String role = jwtUtil.extractClaims(token, c -> c.get("role", String.class));
        assertEquals("ADMIN", role);
    }

    @Test
    void testGenerateTokenWithAgentIdAndScopes() {
        String token = jwtUtil.generateToken("user1", "agent123", List.of("read", "write"));
        assertNotNull(token);
        assertEquals("user1", jwtUtil.extractUsername(token));
        
        String agentId = jwtUtil.extractClaims(token, c -> c.get("agent_id", String.class));
        assertEquals("agent123", agentId);

        List<?> scopes = jwtUtil.extractClaims(token, c -> c.get("scopes", List.class));
        assertNotNull(scopes);
        assertTrue(scopes.contains("read"));
    }

    @Test
    void testExtractExpiration() {
        String token = jwtUtil.generateToken("testuser");
        Date expiration = jwtUtil.extractExpiration(token);
        assertNotNull(expiration);
        assertTrue(expiration.after(new Date()));
    }

    @Test
    void testIsValid_Success() {
        when(userDetails.getUsername()).thenReturn("testuser");
        String token = jwtUtil.generateToken("testuser");

        assertTrue(jwtUtil.isValid(token, userDetails));
    }

    @Test
    void testIsValid_WrongUsername() {
        when(userDetails.getUsername()).thenReturn("wronguser");
        String token = jwtUtil.generateToken("testuser");

        assertFalse(jwtUtil.isValid(token, userDetails));
    }

    @Test
    void testIsExpired() throws InterruptedException {
        // Set a very short expiration
        ReflectionTestUtils.setField(jwtUtil, "expieryDuration", 10L); // 10ms
        String token = jwtUtil.generateToken("testuser");

        // Wait to expire
        Thread.sleep(20L);

        // JWT parsing throws ExpiredJwtException when token is expired
        assertThrows(ExpiredJwtException.class, () -> jwtUtil.isExpired(token));
    }
}
