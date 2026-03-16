package com.kitchome.auth.dao;

import com.kitchome.auth.entity.StoredCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface StoredCredentialRepository extends JpaRepository<StoredCredential, Long> {
    Optional<StoredCredential> findByStorageKey(String storageKey);
    void deleteByStorageKey(String storageKey);
}
