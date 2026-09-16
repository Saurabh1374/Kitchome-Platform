package com.kitchome.auth.controller;

import com.kitchome.auth.entity.AccessPromotionRequest;
import com.kitchome.auth.entity.UserServiceAccessOverview;
import com.kitchome.auth.payload.PromotionApprovalDTO;
import com.kitchome.auth.payload.PromotionRequestDTO;
import com.kitchome.auth.payload.UnifiedProfileResponseDTO;
import com.kitchome.auth.service.PromotionService;
import com.kitchome.common.payload.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/promotions")
@RequiredArgsConstructor
@Slf4j
public class PromotionController {

    private final PromotionService promotionService;

    @PostMapping("/request")
    public ResponseEntity<ApiResponse<AccessPromotionRequest>> submitRequest(
            @RequestBody PromotionRequestDTO dto,
            Authentication auth
    ) {
        AccessPromotionRequest req = promotionService.submitRequest(auth.getName(), dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(req));
    }

    @GetMapping("/my")
    public ResponseEntity<ApiResponse<List<AccessPromotionRequest>>> getMyRequests(Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(promotionService.getUserRequests(auth.getName())));
    }

    @GetMapping("/overview")
    public ResponseEntity<ApiResponse<List<UserServiceAccessOverview>>> getMyOverview(Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(promotionService.getUserAccessOverview(auth.getName())));
    }

    @GetMapping("/admin/pending")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<AccessPromotionRequest>>> getPendingRequests(
            @RequestParam(required = false) String tenantId
    ) {
        return ResponseEntity.ok(ApiResponse.success(promotionService.getPendingRequests(tenantId)));
    }

    @PostMapping("/admin/{id}/review")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<AccessPromotionRequest>> reviewRequest(
            @PathVariable Long id,
            @RequestBody PromotionApprovalDTO approvalDto,
            Authentication auth,
            HttpServletRequest request
    ) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || authHeader.isEmpty()) {
            // Fallback: check cookie if needed
            authHeader = "";
        }
        AccessPromotionRequest reviewed = promotionService.processApproval(id, auth.getName(), authHeader, approvalDto);
        return ResponseEntity.ok(ApiResponse.success(reviewed));
    }

    @GetMapping("/profile-overview")
    public ResponseEntity<ApiResponse<UnifiedProfileResponseDTO>> getProfileOverview(Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(promotionService.getUnifiedProfile(auth.getName())));
    }
}
