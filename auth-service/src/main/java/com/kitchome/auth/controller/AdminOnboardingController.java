package com.kitchome.auth.controller;

import com.kitchome.auth.dao.OrganizationRepository;
import com.kitchome.auth.dao.SharedTokenRevocationRepository;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.entity.Organization;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.service.RefreshTokenService;
import com.kitchome.auth.util.Role;
import com.kitchome.common.payload.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
public class AdminOnboardingController {

    private final UserRepositoryDao userRepo;
    private final OrganizationRepository organizationRepo;
    private final RefreshTokenService refreshTokenService;
    private final SharedTokenRevocationRepository sharedTokenRevocationRepository;
    @Qualifier("ragJdbcTemplate")
    private final JdbcTemplate ragJdbcTemplate;

    @GetMapping("/onboardings/pending")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getPendingOnboardings() {
        List<User> pendingUsers = userRepo.findByEnabledFalse();
        List<Map<String, Object>> result = pendingUsers.stream().map(u -> {
            Map<String, Object> map = new HashMap<>();
            map.put("id", u.getId());
            map.put("username", u.getUsername());
            map.put("email", u.getEmail());
            map.put("emailVerified", u.isEmailVerified());
            map.put("tier", u.getTier());
            map.put("roles", u.getRoles().stream().map(Role::getRole).collect(Collectors.toList()));
            return map;
        }).collect(Collectors.toList());

        return ResponseEntity.ok(ApiResponse.success(result));
    }

    @PostMapping("/onboardings/{id}/approve")
    public ResponseEntity<ApiResponse<String>> approveOnboarding(
            @PathVariable Long id,
            @RequestBody(required = false) Map<String, String> body,
            Authentication auth
    ) {
        User user = userRepo.findById(id).orElseThrow(() -> new RuntimeException("User not found with id: " + id));

        String roleStr = (body != null && body.containsKey("role")) ? body.get("role") : "USER";
        String orgCode = (body != null && body.containsKey("organizationCode")) ? body.get("organizationCode") : null;

        Role selectedRole;
        try {
            selectedRole = Role.valueOf(roleStr.toUpperCase().trim());
        } catch (Exception e) {
            selectedRole = Role.USER;
        }

        user.setEnabled(true);
        user.setRoles(Collections.singleton(selectedRole));

        if (orgCode != null && !orgCode.isBlank()) {
            Organization org = organizationRepo.findByCode(orgCode).orElse(null);
            if (org != null) {
                user.setOrganization(org);
            }
        }

        userRepo.save(user);

        // Sync initial approved tenant membership to downstream PostgreSQL (rag_pg)
        try {
            String tenantId = (user.getOrganization() != null) ? user.getOrganization().getCode() : "default";
            String memId = "mem_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
            double now = System.currentTimeMillis() / 1000.0;
            String approver = (auth != null) ? auth.getName() : "admin";

            String sql = "INSERT INTO user_tenant_memberships (" +
                         "id, user_id, tenant_id, role_in_tenant, status, is_default, approved_by, approved_at, created_at" +
                         ") VALUES (?, ?, ?, ?, 'APPROVED', TRUE, ?, ?, ?) " +
                         "ON CONFLICT(user_id, tenant_id) DO UPDATE SET " +
                         "role_in_tenant = EXCLUDED.role_in_tenant, status = 'APPROVED', approved_by = EXCLUDED.approved_by;";
            ragJdbcTemplate.update(sql, memId, user.getUsername(), tenantId, selectedRole.getRole(), approver, now, now);
            log.info("Provisioned user_tenant_memberships in rag_pg for username={} tenant={}", user.getUsername(), tenantId);
        } catch (Exception ex) {
            log.warn("Could not sync user_tenant_memberships to rag_pg (non-fatal): {}", ex.getMessage());
        }

        return ResponseEntity.ok(ApiResponse.success("User '" + user.getUsername() + "' onboarding approved with role " + selectedRole.getRole()));
    }

    @PostMapping("/onboardings/{id}/reject")
    public ResponseEntity<ApiResponse<String>> rejectOnboarding(
            @PathVariable Long id,
            @RequestBody(required = false) Map<String, String> body
    ) {
        User user = userRepo.findById(id).orElseThrow(() -> new RuntimeException("User not found with id: " + id));
        String username = user.getUsername();
        userRepo.delete(user);
        return ResponseEntity.ok(ApiResponse.success("User onboarding rejected and removed for: " + username));
    }

    @PostMapping("/users/{userId}/invalidate")
    public ResponseEntity<ApiResponse<String>> invalidateUserSessions(@PathVariable String userId) {
        // Try finding user by username or email or numeric ID
        User targetUser = userRepo.findByUsername(userId)
                .or(() -> userRepo.findUserByEmailIgnoreCase(userId))
                .orElse(null);

        if (targetUser == null) {
            try {
                Long numericId = Long.parseLong(userId);
                targetUser = userRepo.findById(numericId).orElse(null);
            } catch (NumberFormatException ignored) {}
        }

        if (targetUser != null) {
            refreshTokenService.invalidateAllForUser(targetUser);
        }

        double nowEpoch = System.currentTimeMillis() / 1000.0;
        sharedTokenRevocationRepository.recordRevocation(userId, nowEpoch);
        if (targetUser != null && targetUser.getUsername() != null && !targetUser.getUsername().equals(userId)) {
            sharedTokenRevocationRepository.recordRevocation(targetUser.getUsername(), nowEpoch);
        }

        log.info("Invalidated cluster sessions and recorded revocation timestamp for userId={}", userId);
        return ResponseEntity.ok(ApiResponse.success("User sessions invalidated across Central Auth and RAG cluster."));
    }

    @GetMapping("/users")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> listAllUsers() {
        List<User> users = userRepo.findAll();
        List<Map<String, Object>> result = users.stream().map(u -> {
            Map<String, Object> map = new HashMap<>();
            map.put("id", u.getId());
            map.put("username", u.getUsername());
            map.put("email", u.getEmail());
            map.put("enabled", u.isEnabled());
            map.put("tier", u.getTier());
            map.put("tenantId", u.getOrganization() != null ? u.getOrganization().getCode() : "default");
            map.put("roles", u.getRoles().stream().map(Role::getRole).collect(Collectors.toList()));
            return map;
        }).collect(Collectors.toList());

        return ResponseEntity.ok(ApiResponse.success(result));
    }
}
