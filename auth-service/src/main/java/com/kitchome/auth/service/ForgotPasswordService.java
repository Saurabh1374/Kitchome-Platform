package com.kitchome.auth.service;

import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.entity.PasswordResetToken;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.util.ErrorCode;
import com.kitchome.auth.Exception.AuthException;
import com.kitchome.auth.dao.PasswordResetTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class ForgotPasswordService {

    private final UserRepositoryDao userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final EmailService emailService;

    public void processForgotPassword(String email) {
        Optional<User> userOptional = userRepository.findUserByEmailIgnoreCase(email);

        if (userOptional.isEmpty()) {
            log.warn("Password reset requested for non-existent email: {}", email);
            // We do nothing to prevent user enumeration
            return;
        }

        User user = userOptional.get();
        String token = UUID.randomUUID().toString();
        PasswordResetToken resetToken = new PasswordResetToken(user, token);

        // Remove existing token if any
        Optional<PasswordResetToken> existingToken = tokenRepository.findByUser(user);
        existingToken.ifPresent(tokenRepository::delete);

        tokenRepository.save(resetToken);

        // Send real email
        emailService.sendPasswordResetEmail(user.getEmail(), token);
    }

    public void validateToken(String token) {
        PasswordResetToken resetToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new AuthException(ErrorCode.TOKEN_NOT_FOUND, "Invalid reset token"));

        if (resetToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new AuthException(ErrorCode.TOKEN_EXPIRED, "Reset token has expired");
        }
    }

    public User getUserByToken(String token) {
        return tokenRepository.findByToken(token)
                .map(PasswordResetToken::getUser)
                .orElseThrow(() -> new AuthException(ErrorCode.TOKEN_NOT_FOUND, "Invalid reset token"));
    }

    public void deleteToken(String token) {
        tokenRepository.findByToken(token).ifPresent(tokenRepository::delete);
    }
}
