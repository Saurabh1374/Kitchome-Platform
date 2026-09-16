package com.kitchome.auth.controller;

import com.kitchome.auth.payload.OrganizationDTO;
import com.kitchome.auth.service.OrganizationService;
import com.kitchome.common.payload.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin/organizations")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
public class OrganizationController {

    private final OrganizationService organizationService;

    @GetMapping
    public ResponseEntity<ApiResponse<List<OrganizationDTO>>> getAllOrganizations() {
        return ResponseEntity.ok(ApiResponse.success(organizationService.getAllOrganizations()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<OrganizationDTO>> getOrganizationById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(organizationService.getOrganizationById(id)));
    }

    @PostMapping
    public ResponseEntity<ApiResponse<OrganizationDTO>> createOrganization(@RequestBody OrganizationDTO dto) {
        OrganizationDTO created = organizationService.createOrganization(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(created));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<OrganizationDTO>> updateOrganization(
            @PathVariable Long id,
            @RequestBody OrganizationDTO dto
    ) {
        OrganizationDTO updated = organizationService.updateOrganization(id, dto);
        return ResponseEntity.ok(ApiResponse.success(updated));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<String>> deleteOrganization(@PathVariable Long id) {
        organizationService.deleteOrganization(id);
        return ResponseEntity.ok(ApiResponse.success("Organization deactivated successfully."));
    }

    @PostMapping("/{code}/assign-user")
    public ResponseEntity<ApiResponse<String>> assignUser(
            @PathVariable String code,
            @RequestBody Map<String, String> payload
    ) {
        String username = payload.get("username");
        organizationService.assignUserToOrganization(username, code);
        return ResponseEntity.ok(ApiResponse.success("User '" + username + "' assigned to organization '" + code + "'."));
    }
}
