package com.kitchome.auth.dao;

import com.kitchome.auth.entity.Organization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OrganizationRepository extends JpaRepository<Organization, Long> {
    Optional<Organization> findByCode(String code);
    Optional<Organization> findByCodeIgnoreCase(String code);
    boolean existsByCodeIgnoreCase(String code);
    List<Organization> findByActiveTrue();
}
