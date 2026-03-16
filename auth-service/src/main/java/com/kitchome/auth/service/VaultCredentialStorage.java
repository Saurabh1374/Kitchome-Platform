package com.kitchome.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kitchome.auth.model.CredentialObject;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;

import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(name = "app.credentials.storage.vault.enabled", havingValue = "true")
public class VaultCredentialStorage implements CredentialStorage {

    private final VaultOperations vaultOperations;
    private final ObjectMapper objectMapper;

    @Override
    public void store(String path, CredentialObject credential) {
        log.info("Storing credential in Vault at path: {}", path);
        try {
            String json = objectMapper.writeValueAsString(credential);
            Map<String, Object> data = objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
            vaultOperations.write(path, data);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize credential for Vault", e);
        }
    }

    @Override
    public Optional<CredentialObject> retrieve(String path) {
        log.info("Retrieving credential from Vault at path: {}", path);
        VaultResponse response = vaultOperations.read(path);
        if (response != null && response.getData() != null) {
            try {
                String json = objectMapper.writeValueAsString(response.getData());
                return Optional.of(objectMapper.readValue(json, CredentialObject.class));
            } catch (JsonProcessingException e) {
                log.error("Failed to deserialize credential from Vault", e);
            }
        }
        return Optional.empty();
    }

    @Override
    public void delete(String path) {
        log.info("Deleting credential from Vault at path: {}", path);
        vaultOperations.delete(path);
    }
}
