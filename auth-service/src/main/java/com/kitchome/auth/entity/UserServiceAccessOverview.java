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
@Table(
    name = "user_service_access_overview",
    uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "service_id"})
)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class UserServiceAccessOverview extends BaseEntity {

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

    @Column(name = "service_role", nullable = false)
    private String serviceRole;

    @Column(name = "clearance_level", nullable = false)
    private Integer clearanceLevel;

    @Column(name = "granted_scopes", length = 500)
    private String grantedScopes;

    @Column(name = "status", nullable = false)
    private String status;

    @Column(name = "last_synced_at")
    private LocalDateTime lastSyncedAt;
}
