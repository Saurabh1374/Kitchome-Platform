package com.kitchome.auth.service;

import com.kitchome.auth.integration.CredentialProvider;
import com.kitchome.auth.model.CredentialObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialLifecycleManagerTest {

    @Mock
    private CredentialStorage credentialStorage;

    @Mock
    private CredentialProvider provider;

    private CredentialLifecycleManager manager;

    @BeforeEach
    void setUp() {
        lenient().when(provider.getProviderId()).thenReturn("google");
        manager = new CredentialLifecycleManager(credentialStorage, List.of(provider));
        ReflectionTestUtils.setField(manager, "pathFormat", "secret/users/%s/%s");
    }

    @Test
    void testGetProviders() {
        List<CredentialProvider> providers = manager.getProviders();
        assertEquals(1, providers.size());
        assertEquals("google", providers.get(0).getProviderId());
    }

    @Test
    void testFindProvider_Found() {
        CredentialProvider found = manager.findProvider("google");
        assertNotNull(found);
        assertEquals("google", found.getProviderId());
    }

    @Test
    void testFindProvider_NotFound() {
        assertThrows(IllegalArgumentException.class, () -> manager.findProvider("github"));
    }

    @Test
    void testStoreCredential() {
        CredentialObject cred = new CredentialObject();
        manager.storeCredential("1", "google", cred);

        assertEquals(1L, cred.getUserId());
        assertEquals("google", cred.getProviderId());
        verify(credentialStorage).store(eq("secret/users/1/google"), eq(cred));
    }

    @Test
    void testGetValidCredential_Success_NoRefresh() {
        CredentialObject cred = new CredentialObject();
        when(credentialStorage.retrieve("secret/users/1/google")).thenReturn(Optional.of(cred));
        when(provider.shouldRefresh(cred)).thenReturn(false);
        when(provider.validate(cred)).thenReturn(true);

        CredentialObject result = manager.getValidCredential("1", "google").block();
        assertNotNull(result);
        assertEquals(cred, result);
    }

    @Test
    void testGetValidCredential_NotFound() {
        when(credentialStorage.retrieve("secret/users/1/google")).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> manager.getValidCredential("1", "google").block());
    }

    @Test
    void testGetValidCredential_Invalid() {
        CredentialObject cred = new CredentialObject();
        when(credentialStorage.retrieve("secret/users/1/google")).thenReturn(Optional.of(cred));
        when(provider.shouldRefresh(cred)).thenReturn(false);
        when(provider.validate(cred)).thenReturn(false);

        RuntimeException ex = assertThrows(RuntimeException.class, () -> manager.getValidCredential("1", "google").block());
        assertTrue(ex.getMessage().contains("Credential is invalid"));
    }

    @Test
    void testGetValidCredential_NeedsRefresh() {
        CredentialObject oldCred = new CredentialObject();
        CredentialObject newCred = new CredentialObject();
        
        when(credentialStorage.retrieve("secret/users/1/google")).thenReturn(Optional.of(oldCred));
        when(provider.shouldRefresh(oldCred)).thenReturn(true);
        when(provider.refresh(oldCred)).thenReturn(Mono.just(newCred));

        CredentialObject result = manager.getValidCredential("1", "google").block();

        assertNotNull(result);
        assertEquals(newCred, result);
        verify(credentialStorage).store("secret/users/1/google", newCred);
    }
}
