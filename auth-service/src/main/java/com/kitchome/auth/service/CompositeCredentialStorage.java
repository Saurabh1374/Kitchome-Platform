package com.kitchome.auth.service;

import com.kitchome.auth.model.CredentialObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Primary
@Service
public class CompositeCredentialStorage implements CredentialStorage {

    private final VaultCredentialStorage vaultStorage;
    private final EncryptedCredentialStorage dbStorage;

    public CompositeCredentialStorage(
            @Autowired(required = false) VaultCredentialStorage vaultStorage,
            @Autowired(required = false) EncryptedCredentialStorage dbStorage) {
        this.vaultStorage = vaultStorage;
        this.dbStorage = dbStorage;
    }

    @Override
    public void store(String path, CredentialObject credential) {
        if (vaultStorage != null) {
            try {
                vaultStorage.store(path, credential);
                return; // successfully stored in primary
            } catch (Exception e) {
                log.warn("Failed to store credential in Vault, falling back to db.", e);
            }
        }
        
        if (dbStorage != null) {
            dbStorage.store(path, credential);
        } else {
            throw new IllegalStateException("No credential storage mechanism available to store path: " + path);
        }
    }

    @Override
    public Optional<CredentialObject> retrieve(String path) {
        if (vaultStorage != null) {
            try {
                Optional<CredentialObject> cred = vaultStorage.retrieve(path);
                if (cred.isPresent()) {
                    return cred;
                }
            } catch (Exception e) {
                log.warn("Failed to retrieve credential from Vault, falling back to db.", e);
            }
        }

        if (dbStorage != null) {
            return dbStorage.retrieve(path);
        }
        
        return Optional.empty();
    }

    @Override
    public void delete(String path) {
        if (vaultStorage != null) {
            try {
                vaultStorage.delete(path);
            } catch (Exception e) {
                log.warn("Failed to delete credential in Vault.", e);
            }
        }
        if (dbStorage != null) {
            try {
                dbStorage.delete(path);
            } catch (Exception e) {
                log.warn("Failed to delete credential in DB.", e);
            }
        }
    }
}
