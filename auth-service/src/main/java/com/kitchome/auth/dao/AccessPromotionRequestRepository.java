package com.kitchome.auth.dao;

import com.kitchome.auth.entity.AccessPromotionRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AccessPromotionRequestRepository extends JpaRepository<AccessPromotionRequest, Long> {
    List<AccessPromotionRequest> findByTenantIdAndStatus(String tenantId, String status);
    List<AccessPromotionRequest> findByStatus(String status);
    List<AccessPromotionRequest> findByUsernameOrderByCreatedAtDesc(String username);
}
