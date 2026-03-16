package com.kitchome.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;

import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class VaultService {

    private final VaultOperations vaultOperations;

    /**
     * Store a secret in Vault.
     * 
     * @param path The path in Vault (e.g., "secret/hubspot")
     * @param data The key-value pairs to store
     */
    public void storeSecret(String path, Map<String, String> data) {
        log.info("Storing secret at path: {}", path);
        vaultOperations.write(path, data);
    }

    /**
     * Retrieve a secret from Vault.
     * 
     * @param path The path in Vault
     * @return Map containing secret data
     */
    @SuppressWarnings("unchecked")
    public Optional<Map<String, Object>> getSecret(String path) {
        log.info("Retrieving secret from path: {}", path);
        VaultResponse response = vaultOperations.read(path);
        if (response != null && response.getData() != null) {
            return Optional.of(response.getData());
        }
        return Optional.empty();
    }

    /**
     * Delete a secret from Vault.
     */
    public void deleteSecret(String path) {
        log.info("Deleting secret from path: {}", path);
        vaultOperations.delete(path);
    }
}
