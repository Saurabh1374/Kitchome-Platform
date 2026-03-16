package com.kitchome.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kitchome.auth.dao.StoredCredentialRepository;
import com.kitchome.auth.entity.StoredCredential;
import com.kitchome.auth.model.CredentialObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.annotation.PostConstruct;
import java.util.Optional;

@Slf4j
@Service
@ConditionalOnProperty(name = "app.credentials.storage.db.enabled", havingValue = "true", matchIfMissing = true)
public class EncryptedCredentialStorage implements CredentialStorage {

    private final StoredCredentialRepository repository;
    private final ObjectMapper objectMapper;
    private final String secretKey;
    private final String salt = "5c0744940b5c369b"; // fixed hex salt for encyptors

    private TextEncryptor textEncryptor;

    public EncryptedCredentialStorage(
            StoredCredentialRepository repository,
            ObjectMapper objectMapper,
            @Value("${jwt.secret:defaultSecretDontUseInProd1234567890}") String secretKey) {
        this.repository = repository;
        this.objectMapper = objectMapper;
        this.secretKey = secretKey;
    }

    @PostConstruct
    public void init() {
        this.textEncryptor = Encryptors.text(secretKey, salt);
    }

    @Override
    @Transactional
    public void store(String path, CredentialObject credential) {
        log.info("Storing encrypted credential in DB at path: {}", path);
        try {
            String json = objectMapper.writeValueAsString(credential);
            String encryptedData = textEncryptor.encrypt(json);

            StoredCredential stored = repository.findByStorageKey(path).orElse(new StoredCredential());
            stored.setStorageKey(path);
            stored.setEncryptedData(encryptedData);
            
            repository.save(stored);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize credential for DB", e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<CredentialObject> retrieve(String path) {
        log.info("Retrieving encrypted credential from DB at path: {}", path);
        return repository.findByStorageKey(path).flatMap(stored -> {
            try {
                String decryptedJson = textEncryptor.decrypt(stored.getEncryptedData());
                return Optional.of(objectMapper.readValue(decryptedJson, CredentialObject.class));
            } catch (Exception e) {
                log.error("Failed to decrypt or deserialize credential from DB. Key or salt might have changed.", e);
                return Optional.empty();
            }
        });
    }

    @Override
    @Transactional
    public void delete(String path) {
        log.info("Deleting encrypted credential from DB at path: {}", path);
        repository.deleteByStorageKey(path);
    }
}
