package com.kitchome.auth.dao;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
@Slf4j
public class SharedTokenRevocationRepository {

    private final JdbcTemplate ragJdbcTemplate;

    public SharedTokenRevocationRepository(@Qualifier("ragJdbcTemplate") JdbcTemplate ragJdbcTemplate) {
        this.ragJdbcTemplate = ragJdbcTemplate;
    }

    public void recordRevocation(String userId, double revokedAtEpochSeconds) {
        try {
            String sql = "INSERT INTO user_tokens_revoked_at (user_id, revoked_at) " +
                         "VALUES (?, ?) " +
                         "ON CONFLICT (user_id) DO UPDATE SET revoked_at = EXCLUDED.revoked_at;";
            ragJdbcTemplate.update(sql, userId, revokedAtEpochSeconds);
            log.info("Recorded token revocation epoch in shared PostgreSQL (rag_pg) for userId={} at {}", userId, revokedAtEpochSeconds);
        } catch (Exception e) {
            log.warn("Failed to write token revocation epoch to shared PostgreSQL (rag_pg) for userId={}: {}", userId, e.getMessage());
        }
    }

    public Double getRevocationTime(String userId) {
        try {
            String sql = "SELECT revoked_at FROM user_tokens_revoked_at WHERE user_id = ?;";
            return ragJdbcTemplate.query(sql, rs -> {
                if (rs.next()) {
                    return rs.getDouble("revoked_at");
                }
                return null;
            }, userId);
        } catch (Exception e) {
            log.warn("Failed to read token revocation epoch from shared PostgreSQL (rag_pg) for userId={}: {}", userId, e.getMessage());
            return null;
        }
    }
}
