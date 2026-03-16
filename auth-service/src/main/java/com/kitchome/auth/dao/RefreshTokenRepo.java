package com.kitchome.auth.dao;

import com.kitchome.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepo extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHashAndValidTrue(String hash);

    Optional<RefreshToken> findByUserAndFingerprintAndValidTrue(com.kitchome.auth.entity.User user, String fingerprint);
}
