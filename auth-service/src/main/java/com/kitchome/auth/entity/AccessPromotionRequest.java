package com.kitchome.auth.entity;

import com.kitchome.common.base.BaseEntity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "access_promotion_requests")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class AccessPromotionRequest extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "service_id", nullable = false)
    private String serviceId;

    @Column(name = "current_clearance")
    private Integer currentClearance;

    @Column(name = "requested_clearance", nullable = false)
    private Integer requestedClearance;

    @Column(name = "current_scopes")
    private String currentScopes;

    @Column(name = "requested_scopes", nullable = false)
    private String requestedScopes;

    @Column(name = "current_role")
    private String currentRole;

    @Column(name = "requested_role")
    private String requestedRole;

    @Column(name = "justification", length = 1000)
    private String justification;

    @Builder.Default
    @Column(name = "status", nullable = false)
    private String status = "PENDING";

    @Column(name = "reviewed_by")
    private String reviewedBy;

    @Column(name = "reviewed_at")
    private LocalDateTime reviewedAt;

    @Column(name = "rejection_reason")
    private String rejectionReason;

    @Builder.Default
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();
}
