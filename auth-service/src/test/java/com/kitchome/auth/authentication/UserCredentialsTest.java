package com.kitchome.auth.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kitchome.auth.Exception.AuthException;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.dao.VerificationTokenRepository;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.entity.VerificationToken;
import com.kitchome.auth.payload.RegisterUserDTO;
import com.kitchome.auth.payload.projection.UserCredProjection;
import com.kitchome.auth.service.EmailService;
import com.kitchome.auth.util.ErrorCode;
import com.kitchome.common.exception.ValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserCredentialsTest {

    @Mock
    private UserRepositoryDao userRepo;
    @Mock
    private PasswordEncoder encryptionStrategy;
    @Mock
    private ObjectMapper mapper;
    @Mock
    private EmailService emailService;
    @Mock
    private VerificationTokenRepository tokenRepository;

    @InjectMocks
    private UserCredentials userCredentials;

    private UserCredProjection mockProjection;
    private User mockUser;
    
    @BeforeEach
    void setUp() {
        mockProjection = mock(UserCredProjection.class);
        mockUser = new User();
        mockUser.setId(1L);
        mockUser.setEmail("test@test.com");
        mockUser.setUsername("testuser");
    }

    @Test
    void testLoadUserByUsername_FoundByEmail() {
        when(userRepo.findByEmailIgnoreCase("test@test.com")).thenReturn(Optional.of(mockProjection));
        when(mockProjection.getUsername()).thenReturn("testuser");
        when(mockProjection.getPassword()).thenReturn("encodedPW");

        UserDetails userDetails = userCredentials.loadUserByUsername("test@test.com");
        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
    }

    @Test
    void testLoadUserByUsername_FoundByUsername() {
        when(userRepo.findByEmailIgnoreCase("testuser")).thenReturn(Optional.empty());
        when(userRepo.findByUsernameIgnoreCase("testuser")).thenReturn(Optional.of(mockProjection));
        when(mockProjection.getUsername()).thenReturn("testuser");
        when(mockProjection.getPassword()).thenReturn("encodedPW");

        UserDetails userDetails = userCredentials.loadUserByUsername("testuser");
        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
    }

    @Test
    void testLoadUserByUsername_NotFound() {
        when(userRepo.findByEmailIgnoreCase("unknown")).thenReturn(Optional.empty());
        when(userRepo.findByUsernameIgnoreCase("unknown")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> userCredentials.loadUserByUsername("unknown"));
    }

    @Test
    void testRegisterUser_NewUser() {
        RegisterUserDTO dto = new RegisterUserDTO();
        dto.setUsername("newuser");
        dto.setEmail("new@test.com");
        dto.setPassword("password");

        when(userRepo.findByEmailIgnoreCase("new@test.com")).thenReturn(Optional.empty());
        when(encryptionStrategy.encode("password")).thenReturn("encodedPW");
        when(userRepo.save(any(User.class))).thenReturn(mockUser);

        Boolean result = userCredentials.registerUser(dto);

        assertTrue(result);
        verify(userRepo).save(any(User.class));
        verify(tokenRepository).save(any(VerificationToken.class));
        verify(emailService).sendVerificationEmail(eq("test@test.com"), anyString());
    }

    @Test
    void testRegisterUser_ExistingVerifiedUser() {
        RegisterUserDTO dto = new RegisterUserDTO();
        dto.setEmail("exist@test.com");

        when(userRepo.findByEmailIgnoreCase("exist@test.com")).thenReturn(Optional.of(mockProjection));
        when(mockProjection.isEmailVerified()).thenReturn(true);

        ValidationException ex = assertThrows(ValidationException.class, () -> userCredentials.registerUser(dto));
        assertNotNull(ex.getErrors());
    }

    @Test
    void testRegisterUser_ExistingUnverifiedUser() {
        RegisterUserDTO dto = new RegisterUserDTO();
        dto.setUsername("existuser");
        dto.setEmail("exist@test.com");
        dto.setPassword("password");

        when(userRepo.findByEmailIgnoreCase("exist@test.com")).thenReturn(Optional.of(mockProjection));
        when(mockProjection.isEmailVerified()).thenReturn(false);
        when(mockProjection.getId()).thenReturn(1L);
        when(userRepo.findById(1L)).thenReturn(Optional.of(mockUser));
        
        VerificationToken oldToken = new VerificationToken(mockUser, "old-token");
        when(tokenRepository.findByUser(mockUser)).thenReturn(Optional.of(oldToken));
        when(encryptionStrategy.encode("password")).thenReturn("encodedPW");
        when(userRepo.save(any(User.class))).thenReturn(mockUser);

        Boolean result = userCredentials.registerUser(dto);

        assertTrue(result);
        verify(tokenRepository).delete(oldToken);
        verify(userRepo).delete(mockUser);
        verify(userRepo).save(any(User.class));
        verify(tokenRepository).save(any(VerificationToken.class));
        verify(emailService).sendVerificationEmail(eq("test@test.com"), anyString());
    }

    @Test
    void testVerifyUser_Success() {
        VerificationToken token = new VerificationToken(mockUser, "valid-token");
        token.setExpiryDate(LocalDateTime.now().plusDays(1));

        when(tokenRepository.findByToken("valid-token")).thenReturn(Optional.of(token));

        userCredentials.verifyUser("valid-token");

        assertTrue(mockUser.isEnabled());
        assertTrue(mockUser.isEmailVerified());
        verify(userRepo).save(mockUser);
        verify(tokenRepository).delete(token);
    }

    @Test
    void testVerifyUser_TokenNotFound() {
        when(tokenRepository.findByToken("invalid")).thenReturn(Optional.empty());

        AuthException ex = assertThrows(AuthException.class, () -> userCredentials.verifyUser("invalid"));
        assertEquals(ErrorCode.TOKEN_NOT_FOUND.getErrorCode(), ex.getErrorCode());
    }

    @Test
    void testVerifyUser_TokenExpired() {
        VerificationToken token = new VerificationToken(mockUser, "expired-token");
        token.setExpiryDate(LocalDateTime.now().minusDays(1));

        when(tokenRepository.findByToken("expired-token")).thenReturn(Optional.of(token));

        AuthException ex = assertThrows(AuthException.class, () -> userCredentials.verifyUser("expired-token"));
        assertEquals(ErrorCode.TOKEN_EXPIRED.getErrorCode(), ex.getErrorCode());
    }

    @Test
    void testResendVerificationLink_Success() {
        when(userRepo.findByEmailIgnoreCase("test@test.com")).thenReturn(Optional.of(mockProjection));
        when(mockProjection.getId()).thenReturn(1L);
        when(mockProjection.getEmail()).thenReturn("test@test.com");
        when(mockProjection.isEnabled()).thenReturn(true);
        when(userRepo.findById(1L)).thenReturn(Optional.of(mockUser));
        
        mockUser.setEnabled(true);
        mockUser.setEmailVerified(false);
        
        VerificationToken oldToken = new VerificationToken(mockUser, "old-token");
        when(tokenRepository.findByUser(mockUser)).thenReturn(Optional.of(oldToken));

        userCredentials.resendVerificationLink("test@test.com");

        verify(tokenRepository).delete(oldToken);
        verify(tokenRepository).save(any(VerificationToken.class));
        verify(emailService).sendVerificationEmail(eq("test@test.com"), anyString());
    }

    @Test
    void testResendVerificationLink_AlreadyVerified() {
        when(userRepo.findByEmailIgnoreCase("test@test.com")).thenReturn(Optional.of(mockProjection));
        when(mockProjection.getId()).thenReturn(1L);
        when(userRepo.findById(1L)).thenReturn(Optional.of(mockUser));

        mockUser.setEnabled(true);
        mockUser.setEmailVerified(true);

        AuthException ex = assertThrows(AuthException.class, () -> userCredentials.resendVerificationLink("test@test.com"));
        assertEquals(ErrorCode.VALIDATION_ERROR.getErrorCode(), ex.getErrorCode());
        assertEquals("Account is already verified", ex.getMessage());
    }

    @Test
    void testResendVerificationLink_UserNotFound() {
        when(userRepo.findByEmailIgnoreCase("unknown@test.com")).thenReturn(Optional.empty());

        AuthException ex = assertThrows(AuthException.class, () -> userCredentials.resendVerificationLink("unknown@test.com"));
        assertEquals(ErrorCode.VALIDATION_ERROR.getErrorCode(), ex.getErrorCode());
    }

    @Test
    void testUpdatePassword() {
        when(encryptionStrategy.encode("newPW")).thenReturn("encodedNewPW");

        userCredentials.updatePassword(mockUser, "newPW");

        assertEquals("encodedNewPW", mockUser.getPassword());
        assertNotNull(mockUser.getPasswordLastUpdated());
        verify(userRepo).save(mockUser);
    }
}
