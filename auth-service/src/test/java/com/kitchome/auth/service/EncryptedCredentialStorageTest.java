package com.kitchome.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kitchome.auth.dao.StoredCredentialRepository;
import com.kitchome.auth.entity.StoredCredential;
import com.kitchome.auth.model.CredentialObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EncryptedCredentialStorageTest {

    @Mock
    private StoredCredentialRepository repository;

    private ObjectMapper objectMapper;

    private EncryptedCredentialStorage storage;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        // A valid strong secret key is required
        String secretKey = "my-super-secret-key!123";
        storage = new EncryptedCredentialStorage(repository, objectMapper, secretKey);
        storage.init();
    }

    @Test
    void testStore_NewEntry() throws Exception {
        CredentialObject cred = new CredentialObject();
        cred.addKey("accessToken", "token123");

        when(repository.findByStorageKey("path/to/cred")).thenReturn(Optional.empty());

        storage.store("path/to/cred", cred);

        ArgumentCaptor<StoredCredential> captor = ArgumentCaptor.forClass(StoredCredential.class);
        verify(repository).save(captor.capture());

        StoredCredential saved = captor.getValue();
        assertEquals("path/to/cred", saved.getStorageKey());
        assertNotNull(saved.getEncryptedData());

        // We can decrypt to verify
        String encrypted = saved.getEncryptedData();
        assertNotEquals("{\"accessToken\":\"token123\"}", encrypted);
    }

    @Test
    void testStore_ExistingEntry() throws Exception {
        CredentialObject cred = new CredentialObject();
        cred.addKey("accessToken", "token123");

        StoredCredential existing = new StoredCredential();
        existing.setStorageKey("path/to/cred");
        existing.setEncryptedData("old-data");

        when(repository.findByStorageKey("path/to/cred")).thenReturn(Optional.of(existing));

        storage.store("path/to/cred", cred);

        verify(repository).save(existing);
        assertNotEquals("old-data", existing.getEncryptedData());
    }

    @Test
    void testRetrieve_Success() throws Exception {
        CredentialObject cred = new CredentialObject();
        cred.addKey("accessToken", "token123");
        cred.setProviderId("github");

        // Manually store encrypt
        storage.store("path/test", cred);
        ArgumentCaptor<StoredCredential> captor = ArgumentCaptor.forClass(StoredCredential.class);
        verify(repository).save(captor.capture());

        StoredCredential dbCred = captor.getValue();

        when(repository.findByStorageKey("path/test")).thenReturn(Optional.of(dbCred));

        Optional<CredentialObject> retrieved = storage.retrieve("path/test");

        assertTrue(retrieved.isPresent());
        assertEquals("token123", retrieved.get().getKeyValue("accessToken").get());
        assertEquals("github", retrieved.get().getProviderId());
    }

    @Test
    void testRetrieve_NotFound() {
        when(repository.findByStorageKey("path/test")).thenReturn(Optional.empty());

        Optional<CredentialObject> retrieved = storage.retrieve("path/test");

        assertFalse(retrieved.isPresent());
    }

    @Test
    void testRetrieve_DecryptionFails() {
        StoredCredential dbCred = new StoredCredential();
        dbCred.setStorageKey("path/test");
        dbCred.setEncryptedData("invalid-encrypted-data---not-real");

        when(repository.findByStorageKey("path/test")).thenReturn(Optional.of(dbCred));

        Optional<CredentialObject> retrieved = storage.retrieve("path/test");

        // Should catch the exception and return Optional.empty()
        assertFalse(retrieved.isPresent());
    }

    @Test
    void testDelete() {
        storage.delete("path/test");
        verify(repository).deleteByStorageKey("path/test");
    }
}
