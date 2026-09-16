package com.kitchome.auth.dao;

import com.kitchome.auth.entity.UserServiceAccessOverview;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserServiceAccessOverviewRepository extends JpaRepository<UserServiceAccessOverview, Long> {
    Optional<UserServiceAccessOverview> findByUsernameAndServiceId(String username, String serviceId);
    Optional<UserServiceAccessOverview> findByUserIdAndServiceId(Long userId, String serviceId);
    List<UserServiceAccessOverview> findByTenantId(String tenantId);
    List<UserServiceAccessOverview> findByUsername(String username);
}
