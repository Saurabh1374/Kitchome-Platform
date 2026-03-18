package com.kitchome.auth.service;

import com.kitchome.auth.Exception.AuthException;
import com.kitchome.auth.dao.PasswordResetTokenRepository;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.entity.PasswordResetToken;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.util.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ForgotPasswordServiceTest {

    @Mock
    private UserRepositoryDao userRepository;

    @Mock
    private PasswordResetTokenRepository tokenRepository;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private ForgotPasswordService forgotPasswordService;

    private User user;
    private PasswordResetToken token;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");

        token = new PasswordResetToken(user, "valid-token");
    }

    @Test
    void testProcessForgotPassword_UserExists_NoExistingToken() {
        when(userRepository.findUserByEmailIgnoreCase("test@example.com")).thenReturn(Optional.of(user));
        when(tokenRepository.findByUser(user)).thenReturn(Optional.empty());

        forgotPasswordService.processForgotPassword("test@example.com");

        ArgumentCaptor<PasswordResetToken> tokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepository).save(tokenCaptor.capture());
        
        PasswordResetToken savedToken = tokenCaptor.getValue();
        assertNotNull(savedToken.getToken());
        assertEquals(user, savedToken.getUser());

        verify(emailService).sendPasswordResetEmail(eq("test@example.com"), eq(savedToken.getToken()));
    }

    @Test
    void testProcessForgotPassword_UserExists_ExistingToken() {
        PasswordResetToken oldToken = new PasswordResetToken(user, "old-token");
        when(userRepository.findUserByEmailIgnoreCase("test@example.com")).thenReturn(Optional.of(user));
        when(tokenRepository.findByUser(user)).thenReturn(Optional.of(oldToken));

        forgotPasswordService.processForgotPassword("test@example.com");

        verify(tokenRepository).delete(oldToken);
        verify(tokenRepository).save(any(PasswordResetToken.class));
        verify(emailService).sendPasswordResetEmail(eq("test@example.com"), anyString());
    }

    @Test
    void testProcessForgotPassword_UserDoesNotExist() {
        when(userRepository.findUserByEmailIgnoreCase("unknown@example.com")).thenReturn(Optional.empty());

        forgotPasswordService.processForgotPassword("unknown@example.com");

        verify(tokenRepository, never()).findByUser(any());
        verify(tokenRepository, never()).save(any());
        verify(emailService, never()).sendPasswordResetEmail(anyString(), anyString());
    }

    @Test
    void testValidateToken_Valid() {
        when(tokenRepository.findByToken("valid-token")).thenReturn(Optional.of(token));
        
        // This should run without throwing any exception
        assertDoesNotThrow(() -> forgotPasswordService.validateToken("valid-token"));
    }

    @Test
    void testValidateToken_NotFound() {
        when(tokenRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

        AuthException ex = assertThrows(AuthException.class, () -> forgotPasswordService.validateToken("invalid-token"));
        assertEquals(ErrorCode.TOKEN_NOT_FOUND.getErrorCode(), ex.getErrorCode());
    }

    @Test
    void testValidateToken_Expired() {
        PasswordResetToken expiredToken = new PasswordResetToken(user, "expired");
        expiredToken.setExpiryDate(LocalDateTime.now().minusDays(1)); // Make it expired
        when(tokenRepository.findByToken("expired")).thenReturn(Optional.of(expiredToken));

        AuthException ex = assertThrows(AuthException.class, () -> forgotPasswordService.validateToken("expired"));
        assertEquals(ErrorCode.TOKEN_EXPIRED.getErrorCode(), ex.getErrorCode());
    }

    @Test
    void testGetUserByToken_Found() {
        when(tokenRepository.findByToken("valid-token")).thenReturn(Optional.of(token));

        User foundUser = forgotPasswordService.getUserByToken("valid-token");
        assertNotNull(foundUser);
        assertEquals(user, foundUser);
    }

    @Test
    void testGetUserByToken_NotFound() {
        when(tokenRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

        AuthException ex = assertThrows(AuthException.class, () -> forgotPasswordService.getUserByToken("invalid-token"));
        assertEquals(ErrorCode.TOKEN_NOT_FOUND.getErrorCode(), ex.getErrorCode());
    }

    @Test
    void testDeleteToken_Exists() {
        when(tokenRepository.findByToken("valid-token")).thenReturn(Optional.of(token));

        forgotPasswordService.deleteToken("valid-token");

        verify(tokenRepository).delete(token);
    }

    @Test
    void testDeleteToken_DoesNotExists() {
        when(tokenRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

        forgotPasswordService.deleteToken("invalid-token");

        verify(tokenRepository, never()).delete(any());
    }
}
