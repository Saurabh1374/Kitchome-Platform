package com.kitchome.auth.service;

import com.kitchome.auth.dao.RefreshTokenRepo;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.entity.RefreshToken;
import com.kitchome.auth.entity.User;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepo tokenRepo;

    @Mock
    private UserRepositoryDao userRepo;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    private User mockUser;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(refreshTokenService, "expiryDuration", 86400000L); // 1 day
        mockUser = new User();
        mockUser.setId(1L);
        mockUser.setUsername("testuser");
    }

    @Test
    void testGenerateAndStoreRefreshToken_NewDevice() {
        when(userRepo.findByUsername("testuser")).thenReturn(Optional.of(mockUser));
        when(tokenRepo.findByUserAndFingerprintAndValidTrue(mockUser, "fingerprint1")).thenReturn(Optional.empty());
        when(tokenRepo.save(any(RefreshToken.class))).thenAnswer(i -> i.getArguments()[0]);

        RefreshToken token = refreshTokenService.generateAndStoreRefreshToken("testuser", "fingerprint1", "127.0.0.1", "Mozilla");

        assertNotNull(token);
        assertEquals(mockUser, token.getUser());
        assertEquals("fingerprint1", token.getFingerprint());
        assertEquals("127.0.0.1", token.getIp());
        assertEquals("Mozilla", token.getUserAgent());
        assertTrue(token.isValid());
        assertNotNull(token.getToken());
        assertNotNull(token.getTokenHash());
        
        String expectedHash = DigestUtils.sha256Hex(token.getToken());
        assertEquals(expectedHash, token.getTokenHash());

        verify(tokenRepo, times(1)).save(token);
    }

    @Test
    void testGenerateAndStoreRefreshToken_ExistingDevice() {
        when(userRepo.findByUsername("testuser")).thenReturn(Optional.of(mockUser));
        
        RefreshToken existingToken = new RefreshToken();
        existingToken.setValid(true);
        when(tokenRepo.findByUserAndFingerprintAndValidTrue(mockUser, "fingerprint1")).thenReturn(Optional.of(existingToken));
        
        when(tokenRepo.save(any(RefreshToken.class))).thenAnswer(i -> i.getArguments()[0]);

        RefreshToken token = refreshTokenService.generateAndStoreRefreshToken("testuser", "fingerprint1", "127.0.0.1", "Mozilla");

        assertFalse(existingToken.isValid());
        verify(tokenRepo).save(existingToken); // 1st save for invalidation
        verify(tokenRepo).save(token); // 2nd save for the new token
    }

    @Test
    void testValidate_Success() {
        String rawToken = "my-secure-token";
        String hash = DigestUtils.sha256Hex(rawToken);

        RefreshToken validToken = new RefreshToken();
        validToken.setValid(true);
        validToken.setExpiresAt(LocalDateTime.now().plusDays(1));

        when(tokenRepo.findByTokenHashAndValidTrue(hash)).thenReturn(Optional.of(validToken));

        RefreshToken result = refreshTokenService.validate(rawToken);
        assertEquals(validToken, result);
    }

    @Test
    void testValidate_Expired() {
        String rawToken = "my-secure-token";
        String hash = DigestUtils.sha256Hex(rawToken);

        RefreshToken expiredToken = new RefreshToken();
        expiredToken.setValid(true);
        expiredToken.setExpiresAt(LocalDateTime.now().minusDays(1)); // expired

        when(tokenRepo.findByTokenHashAndValidTrue(hash)).thenReturn(Optional.of(expiredToken));

        RuntimeException ex = assertThrows(RuntimeException.class, () -> refreshTokenService.validate(rawToken));
        assertEquals("Refresh token expired", ex.getMessage());
    }

    @Test
    void testValidate_NotFoundOrInvalid() {
        String rawToken = "my-secure-token";
        String hash = DigestUtils.sha256Hex(rawToken);

        when(tokenRepo.findByTokenHashAndValidTrue(hash)).thenReturn(Optional.empty());

        RuntimeException ex = assertThrows(RuntimeException.class, () -> refreshTokenService.validate(rawToken));
        assertEquals("Invalid or expired refresh token", ex.getMessage());
    }

    @Test
    void testInvalidate() {
        RefreshToken token = new RefreshToken();
        token.setValid(true);

        refreshTokenService.invalidate(token);

        assertFalse(token.isValid());
        verify(tokenRepo).save(token);
    }
}
