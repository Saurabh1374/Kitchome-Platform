package com.kitchome.auth.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

import com.kitchome.common.base.BaseEntity;
import lombok.EqualsAndHashCode;

@Entity
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false)
@Table(name = "verification_token")
public class VerificationToken extends BaseEntity {
    @Id
    @GeneratedValue
    private UUID id;

    private String token;

    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;

    private LocalDateTime expiryDate;

    public VerificationToken(User user, String token) {
        this.user = user;
        this.token = token;
        // 24 hours expiry for email verification
        this.expiryDate = LocalDateTime.now().plusHours(24);
    }
}
