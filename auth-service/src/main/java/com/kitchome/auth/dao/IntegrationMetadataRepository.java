package com.kitchome.auth.dao;

import com.kitchome.auth.entity.IntegrationMetadata;
import com.kitchome.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface IntegrationMetadataRepository extends JpaRepository<IntegrationMetadata, Long> {
    List<IntegrationMetadata> findByUser(User user);

    Optional<IntegrationMetadata> findByServiceNameAndUser(String serviceName, User user);
}
