package com.kitchome.auth.service;

import com.kitchome.auth.dao.RefreshTokenRepo;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.entity.RefreshToken;
import com.kitchome.auth.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.time.temporal.Temporal;
import java.time.temporal.TemporalAmount;
import java.util.UUID;

@Data
@RequiredArgsConstructor
@Service
public class RefreshTokenService {
    private final RefreshTokenRepo tokenRepo;
    private final UserRepositoryDao userRepo;

    @Value("${jwt.refresh-expiration-ms}")
    private long expiryDuration;

    public RefreshToken generateAndStoreRefreshToken(String username, String fingerprint, String ip, String ua) {
        User user = userRepo.findByUsername(username).orElseThrow();

        // Mitigation for Token Flooding: Revoke any existing valid token for this
        // device
        tokenRepo.findByUserAndFingerprintAndValidTrue(user, fingerprint)
                .ifPresent(existingToken -> {
                    existingToken.setValid(false);
                    tokenRepo.save(existingToken);
                });

        String token = UUID.randomUUID().toString();
        String hash = DigestUtils.sha256Hex(token);
        RefreshToken rt = new RefreshToken();
        rt.setUser(user);
        rt.setTokenHash(hash);
        rt.setFingerprint(fingerprint);
        rt.setIp(ip);
        rt.setUserAgent(ua);
        rt.setIssuedAt(LocalDateTime.now());
        rt.setExpiresAt(LocalDateTime.now().plus(expiryDuration, ChronoUnit.MILLIS));
        rt.setValid(true);

        tokenRepo.save(rt);
        rt.setToken(token); // not persisted

        return rt;
    }

    public RefreshToken validate(String rawToken) {
        String hash = DigestUtils.sha256Hex(rawToken);
        RefreshToken token = tokenRepo.findByTokenHashAndValidTrue(hash)
                .orElseThrow(() -> new RuntimeException("Invalid or expired refresh token"));

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        return token;
    }

    @Transactional
    public void invalidate(RefreshToken token) {
        token.setValid(false);
        tokenRepo.save(token);
    }
}
