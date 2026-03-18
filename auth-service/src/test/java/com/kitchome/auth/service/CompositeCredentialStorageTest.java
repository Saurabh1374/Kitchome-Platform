package com.kitchome.auth.service;

import com.kitchome.auth.model.CredentialObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CompositeCredentialStorageTest {

    @Mock
    private VaultCredentialStorage vaultStorage;

    @Mock
    private EncryptedCredentialStorage dbStorage;

    private CompositeCredentialStorage storageBoth;
    private CompositeCredentialStorage storageOnlyDb;
    private CompositeCredentialStorage storageOnlyVault;

    private CredentialObject credential;

    @BeforeEach
    void setUp() {
        storageBoth = new CompositeCredentialStorage(vaultStorage, dbStorage);
        storageOnlyDb = new CompositeCredentialStorage(null, dbStorage);
        storageOnlyVault = new CompositeCredentialStorage(vaultStorage, null);

        credential = new CredentialObject();
    }

    @Test
    void testStore_VaultSuccess() {
        storageBoth.store("path", credential);
        verify(vaultStorage).store("path", credential);
        verify(dbStorage, never()).store(any(), any());
    }

    @Test
    void testStore_VaultThrows_FallbackToDb() {
        doThrow(new RuntimeException("Vault err")).when(vaultStorage).store("path", credential);
        
        storageBoth.store("path", credential);
        
        verify(vaultStorage).store("path", credential);
        verify(dbStorage).store("path", credential);
    }

    @Test
    void testStore_OnlyDb() {
        storageOnlyDb.store("path", credential);
        verify(dbStorage).store("path", credential);
    }

    @Test
    void testStore_NoStorageAvailable() {
        CompositeCredentialStorage emptyStorage = new CompositeCredentialStorage(null, null);
        assertThrows(IllegalStateException.class, () -> emptyStorage.store("path", credential));
    }

    @Test
    void testRetrieve_VaultSuccess() {
        when(vaultStorage.retrieve("path")).thenReturn(Optional.of(credential));
        
        Optional<CredentialObject> result = storageBoth.retrieve("path");
        
        assertTrue(result.isPresent());
        assertEquals(credential, result.get());
        verify(dbStorage, never()).retrieve(any());
    }

    @Test
    void testRetrieve_VaultEmpty_FallbackToDb() {
        when(vaultStorage.retrieve("path")).thenReturn(Optional.empty());
        when(dbStorage.retrieve("path")).thenReturn(Optional.of(credential));
        
        Optional<CredentialObject> result = storageBoth.retrieve("path");
        
        assertTrue(result.isPresent());
        assertEquals(credential, result.get());
    }

    @Test
    void testRetrieve_VaultThrows_FallbackToDb() {
        when(vaultStorage.retrieve("path")).thenThrow(new RuntimeException("Err"));
        when(dbStorage.retrieve("path")).thenReturn(Optional.of(credential));
        
        Optional<CredentialObject> result = storageBoth.retrieve("path");
        
        assertTrue(result.isPresent());
        assertEquals(credential, result.get());
    }

    @Test
    void testRetrieve_OnlyDb() {
        when(dbStorage.retrieve("path")).thenReturn(Optional.of(credential));
        
        Optional<CredentialObject> result = storageOnlyDb.retrieve("path");
        
        assertTrue(result.isPresent());
    }

    @Test
    void testRetrieve_NoStorage() {
        CompositeCredentialStorage emptyStorage = new CompositeCredentialStorage(null, null);
        Optional<CredentialObject> result = emptyStorage.retrieve("path");
        assertFalse(result.isPresent());
    }

    @Test
    void testDelete_BothSuccess() {
        storageBoth.delete("path");
        
        verify(vaultStorage).delete("path");
        verify(dbStorage).delete("path");
    }

    @Test
    void testDelete_VaultThrows_DbStillDeletes() {
        doThrow(new RuntimeException("err")).when(vaultStorage).delete("path");
        
        storageBoth.delete("path");
        
        verify(vaultStorage).delete("path");
        verify(dbStorage).delete("path");
    }

    @Test
    void testDelete_DbThrows() {
        doThrow(new RuntimeException("err")).when(dbStorage).delete("path");
        
        storageBoth.delete("path");
        
        verify(vaultStorage).delete("path");
        verify(dbStorage).delete("path");
    }

    @Test
    void testDelete_OnlyVault() {
        storageOnlyVault.delete("path");
        verify(vaultStorage).delete("path");
    }
}
