package com.kitchome.auth.service;

import com.kitchome.auth.dao.AccessPromotionRequestRepository;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.dao.UserServiceAccessOverviewRepository;
import com.kitchome.auth.entity.AccessPromotionRequest;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.entity.UserServiceAccessOverview;
import com.kitchome.auth.payload.PromotionApprovalDTO;
import com.kitchome.auth.payload.UnifiedProfileResponseDTO;
import com.kitchome.auth.payload.PromotionRequestDTO;
import com.kitchome.common.exception.ValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class PromotionService {

    private final AccessPromotionRequestRepository promotionRepo;
    private final UserServiceAccessOverviewRepository accessOverviewRepo;
    private final UserRepositoryDao userRepo;
    private final RagServiceClient ragServiceClient;

    private User findUserOrThrow(String username) {
        return userRepo.findUserByUsernameIgnoreCase(username)
                .or(() -> userRepo.findUserByEmailIgnoreCase(username))
                .orElseThrow(() -> new ValidationException("User not found: " + username, "VALIDATION_FAILED"));
    }

    @Transactional
    public AccessPromotionRequest submitRequest(String username, PromotionRequestDTO dto) {
        User user = findUserOrThrow(username);
        String canonicalUsername = user.getUsername();

        String tenantId = (user.getOrganization() != null) ? user.getOrganization().getCode() : "default";
        String serviceId = (dto.getServiceId() != null) ? dto.getServiceId() : "kitchome-rag";

        Optional<UserServiceAccessOverview> existingOpt = accessOverviewRepo.findByUsernameAndServiceId(canonicalUsername, serviceId);
        int currentClearance = existingOpt.map(UserServiceAccessOverview::getClearanceLevel).orElse(1);
        String currentScopes = existingOpt.map(UserServiceAccessOverview::getGrantedScopes).orElse("rag:read");
        String currentRole = existingOpt.map(UserServiceAccessOverview::getServiceRole).orElse("member");

        String reqScopes = (dto.getRequestedScopes() != null) ? String.join(",", dto.getRequestedScopes()) : "rag:read";
        int reqClearance = (dto.getRequestedClearance() != null) ? dto.getRequestedClearance() : currentClearance;

        AccessPromotionRequest req = AccessPromotionRequest.builder()
                .user(user)
                .username(canonicalUsername)
                .tenantId(tenantId)
                .serviceId(serviceId)
                .currentClearance(currentClearance)
                .requestedClearance(reqClearance)
                .currentScopes(currentScopes)
                .requestedScopes(reqScopes)
                .currentRole(currentRole)
                .requestedRole(dto.getRequestedRole() != null ? dto.getRequestedRole() : currentRole)
                .justification(dto.getJustification())
                .status("PENDING")
                .createdAt(LocalDateTime.now())
                .build();

        AccessPromotionRequest saved = promotionRepo.save(req);
        log.info("User '{}' submitted promotion request ID={}", canonicalUsername, saved.getId());
        return saved;
    }

    @Transactional
    public AccessPromotionRequest processApproval(
            Long requestId,
            String adminUsername,
            String adminToken,
            PromotionApprovalDTO approvalDto
    ) {
        AccessPromotionRequest req = promotionRepo.findById(requestId)
                .orElseThrow(() -> new ValidationException("Promotion request not found with ID: " + requestId, "VALIDATION_FAILED"));

        if (!"PENDING".equalsIgnoreCase(req.getStatus())) {
            throw new ValidationException("Request is already processed: " + req.getStatus(), "VALIDATION_FAILED");
        }

        req.setReviewedBy(adminUsername);
        req.setReviewedAt(LocalDateTime.now());

        if (!approvalDto.isApproved()) {
            req.setStatus("REJECTED");
            req.setRejectionReason(approvalDto.getReason() != null ? approvalDto.getReason() : "Declined by admin");
            return promotionRepo.save(req);
        }

        // Approved -> Dispatch update to downstream service (Kitchome RAG)
        List<String> scopesList = Arrays.asList(req.getRequestedScopes().split(","));
        try {
            ragServiceClient.updateAccess(
                    adminToken,
                    req.getUsername(),
                    req.getRequestedClearance(),
                    req.getRequestedRole(),
                    scopesList
            ).block(); // Synchronous confirmation
        } catch (Exception e) {
            log.error("Failed downstream API call to Kitchome RAG: {}", e.getMessage());
            throw new ValidationException("Failed to update access in downstream service: " + e.getMessage(), "VALIDATION_FAILED");
        }

        // Downstream succeeded -> Update upstream look-up table (user_service_access_overview)
        UserServiceAccessOverview overview = accessOverviewRepo
                .findByUsernameAndServiceId(req.getUsername(), req.getServiceId())
                .orElseGet(() -> UserServiceAccessOverview.builder()
                        .user(req.getUser())
                        .username(req.getUsername())
                        .tenantId(req.getTenantId())
                        .serviceId(req.getServiceId())
                        .build());

        overview.setClearanceLevel(req.getRequestedClearance());
        overview.setGrantedScopes(req.getRequestedScopes());
        overview.setServiceRole(req.getRequestedRole());
        overview.setStatus("APPROVED");
        overview.setLastSyncedAt(LocalDateTime.now());
        accessOverviewRepo.save(overview);

        req.setStatus("APPROVED");
        AccessPromotionRequest updated = promotionRepo.save(req);
        log.info("Promotion request ID={} approved by '{}'", requestId, adminUsername);
        return updated;
    }

    @Transactional(readOnly = true)
    public List<AccessPromotionRequest> getPendingRequests(String tenantId) {
        if (tenantId != null && !tenantId.isEmpty()) {
            return promotionRepo.findByTenantIdAndStatus(tenantId, "PENDING");
        }
        return promotionRepo.findByStatus("PENDING");
    }

    @Transactional(readOnly = true)
    public List<AccessPromotionRequest> getUserRequests(String username) {
        String canonical = userRepo.findUserByUsernameIgnoreCase(username)
                .or(() -> userRepo.findUserByEmailIgnoreCase(username))
                .map(User::getUsername).orElse(username);
        return promotionRepo.findByUsernameOrderByCreatedAtDesc(canonical);
    }

    @Transactional(readOnly = true)
    public List<UserServiceAccessOverview> getUserAccessOverview(String username) {
        String canonical = userRepo.findUserByUsernameIgnoreCase(username)
                .or(() -> userRepo.findUserByEmailIgnoreCase(username))
                .map(User::getUsername).orElse(username);
        return accessOverviewRepo.findByUsername(canonical);
    }

    @Transactional
    public UnifiedProfileResponseDTO getUnifiedProfile(String username) {
        User user = findUserOrThrow(username);
        String canonicalUsername = user.getUsername();

        String tenantId = (user.getOrganization() != null) ? user.getOrganization().getCode() : "default";
        String orgName = (user.getOrganization() != null) ? user.getOrganization().getName() : "Personal / Default";
        String roles = user.getRoles().stream().map(Enum::name).collect(java.util.stream.Collectors.joining(", "));

        List<UserServiceAccessOverview> overviews = accessOverviewRepo.findByUsername(canonicalUsername);
        if (overviews.isEmpty()) {
            boolean isAdmin = user.getRoles().stream().anyMatch(r -> r.name().contains("ADMIN"));
            UserServiceAccessOverview initialOverview = UserServiceAccessOverview.builder()
                    .user(user)
                    .username(canonicalUsername)
                    .tenantId(tenantId)
                    .serviceId("kitchome-rag")
                    .serviceRole(isAdmin ? "admin" : "member")
                    .clearanceLevel(isAdmin ? 3 : 1)
                    .grantedScopes(isAdmin ? "rag:read,ingestion:write,admin:manage" : "rag:read")
                    .status("APPROVED")
                    .lastSyncedAt(LocalDateTime.now())
                    .build();
            accessOverviewRepo.save(initialOverview);
            overviews = List.of(initialOverview);
        }

        List<AccessPromotionRequest> requests = promotionRepo.findByUsernameOrderByCreatedAtDesc(canonicalUsername);

        return UnifiedProfileResponseDTO.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(roles)
                .tier(user.getTier() != null ? user.getTier() : "free")
                .tenantId(tenantId)
                .organizationName(orgName)
                .serviceAccess(overviews)
                .pendingRequests(requests)
                .build();
    }
}
