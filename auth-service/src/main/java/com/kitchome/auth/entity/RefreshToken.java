package com.kitchome.auth.entity;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

import lombok.EqualsAndHashCode;
import com.kitchome.common.base.BaseEntity;

@Entity
@Data
@Table(name = "tokens")
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class RefreshToken extends BaseEntity {
        @Id
        @GeneratedValue
        @Column(columnDefinition = "uniqueidentifier", updatable = false, nullable = false)
        private UUID id;

        @ManyToOne
        @JoinColumn(name = "user_id")
        private User user;

        private String tokenHash;
        private String fingerprint;
        private String ip;
        private String userAgent;

        private LocalDateTime issuedAt;
        private LocalDateTime expiresAt;
        private boolean valid = true;

        @Transient
        private String token;

}
