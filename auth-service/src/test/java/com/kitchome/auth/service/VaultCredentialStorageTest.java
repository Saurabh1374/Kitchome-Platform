package com.kitchome.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kitchome.auth.model.CredentialObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VaultCredentialStorageTest {

    @Mock
    private VaultOperations vaultOperations;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private VaultCredentialStorage vaultCredentialStorage;

    @Test
    void testStore_Success() throws Exception {
        CredentialObject cred = new CredentialObject();
        cred.addKey("accessToken", "token123");

        String jsonString = "{\"keys\":[{\"keyName\":\"accessToken\",\"keyValue\":\"token123\"}]}";
        Map<String, Object> map = new HashMap<>();
        map.put("keys", "...");

        when(objectMapper.writeValueAsString(cred)).thenReturn(jsonString);
        when(objectMapper.readValue(eq(jsonString), any(TypeReference.class))).thenReturn(map);

        vaultCredentialStorage.store("secret/path", cred);

        verify(vaultOperations).write("secret/path", map);
    }

    @Test
    void testStore_JsonProcessingException() throws Exception {
        CredentialObject cred = new CredentialObject();

        when(objectMapper.writeValueAsString(cred)).thenThrow(new JsonProcessingException("err") {});

        RuntimeException ex = assertThrows(RuntimeException.class, () -> vaultCredentialStorage.store("secret/path", cred));
        assertTrue(ex.getMessage().contains("Failed to serialize credential"));
    }

    @Test
    void testRetrieve_Success() throws Exception {
        VaultResponse response = new VaultResponse();
        Map<String, Object> data = new HashMap<>();
        data.put("accessToken", "token123");
        response.setData(data);

        when(vaultOperations.read("secret/path")).thenReturn(response);

        String jsonString = "{\"accessToken\":\"token123\"}";
        when(objectMapper.writeValueAsString(data)).thenReturn(jsonString);

        CredentialObject cred = new CredentialObject();
        cred.addKey("accessToken", "token123");
        when(objectMapper.readValue(jsonString, CredentialObject.class)).thenReturn(cred);

        Optional<CredentialObject> result = vaultCredentialStorage.retrieve("secret/path");

        assertTrue(result.isPresent());
        assertEquals(cred, result.get());
    }

    @Test
    void testRetrieve_NotFoundOrNullData() {
        when(vaultOperations.read("secret/path")).thenReturn(null);

        Optional<CredentialObject> result = vaultCredentialStorage.retrieve("secret/path");

        assertFalse(result.isPresent());
    }

    @Test
    void testRetrieve_JsonProcessingException() throws Exception {
        VaultResponse response = new VaultResponse();
        Map<String, Object> data = new HashMap<>();
        response.setData(data);

        when(vaultOperations.read("secret/path")).thenReturn(response);
        when(objectMapper.writeValueAsString(data)).thenThrow(new JsonProcessingException("err") {});

        Optional<CredentialObject> result = vaultCredentialStorage.retrieve("secret/path");

        assertFalse(result.isPresent());
    }

    @Test
    void testDelete_Success() {
        vaultCredentialStorage.delete("secret/path");
        verify(vaultOperations).delete("secret/path");
    }
}
