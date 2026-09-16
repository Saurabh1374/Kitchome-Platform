package com.kitchome.auth.service;

import com.kitchome.auth.dao.OrganizationRepository;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.entity.Organization;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.payload.OrganizationDTO;
import com.kitchome.common.exception.ValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class OrganizationService {

    private final OrganizationRepository organizationRepository;
    private final UserRepositoryDao userRepository;

    @Transactional(readOnly = true)
    public List<OrganizationDTO> getAllOrganizations() {
        return organizationRepository.findAll().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public OrganizationDTO getOrganizationById(Long id) {
        Organization org = organizationRepository.findById(id)
                .orElseThrow(() -> new ValidationException("Organization not found with ID: " + id, "VALIDATION_FAILED"));
        return mapToDTO(org);
    }

    @Transactional(readOnly = true)
    public OrganizationDTO getOrganizationByCode(String code) {
        Organization org = organizationRepository.findByCodeIgnoreCase(code)
                .orElseThrow(() -> new ValidationException("Organization not found with code: " + code, "VALIDATION_FAILED"));
        return mapToDTO(org);
    }

    @Transactional
    public OrganizationDTO createOrganization(OrganizationDTO dto) {
        if (dto.getCode() == null || dto.getCode().trim().isEmpty()) {
            throw new ValidationException("Organization tenant code is required.", "VALIDATION_FAILED");
        }
        String cleanCode = dto.getCode().trim().toLowerCase();
        if (organizationRepository.existsByCodeIgnoreCase(cleanCode)) {
            throw new ValidationException("Organization with code  + cleanCode +  already exists.", "VALIDATION_FAILED");
        }

        Organization org = new Organization();
        org.setName(dto.getName());
        org.setCode(cleanCode);
        org.setDescription(dto.getDescription());
        org.setActive(true);

        Organization saved = organizationRepository.save(org);
        log.info("Admin created organization: id={}, code={}", saved.getId(), saved.getCode());
        return mapToDTO(saved);
    }

    @Transactional
    public OrganizationDTO updateOrganization(Long id, OrganizationDTO dto) {
        Organization org = organizationRepository.findById(id)
                .orElseThrow(() -> new ValidationException("Organization not found with ID: " + id, "VALIDATION_FAILED"));

        if (dto.getName() != null) org.setName(dto.getName());
        if (dto.getDescription() != null) org.setDescription(dto.getDescription());
        org.setActive(dto.isActive());

        Organization updated = organizationRepository.save(org);
        log.info("Admin updated organization: id={}, code={}", updated.getId(), updated.getCode());
        return mapToDTO(updated);
    }

    @Transactional
    public void deleteOrganization(Long id) {
        Organization org = organizationRepository.findById(id)
                .orElseThrow(() -> new ValidationException("Organization not found with ID: " + id, "VALIDATION_FAILED"));
        org.setActive(false);
        organizationRepository.save(org);
        log.info("Admin deactivated organization: id={}, code={}", org.getId(), org.getCode());
    }

    @Transactional
    public void assignUserToOrganization(String username, String orgCode) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ValidationException("User not found: " + username, "VALIDATION_FAILED"));
        Organization org = organizationRepository.findByCodeIgnoreCase(orgCode)
                .orElseThrow(() -> new ValidationException("Organization not found: " + orgCode, "VALIDATION_FAILED"));

        user.setOrganization(org);
        userRepository.save(user);
        log.info("Assigned user {} to organization {}", username, orgCode);
    }

    private OrganizationDTO mapToDTO(Organization org) {
        return OrganizationDTO.builder()
                .id(org.getId())
                .name(org.getName())
                .code(org.getCode())
                .description(org.getDescription())
                .active(org.isActive())
                .build();
    }
}
