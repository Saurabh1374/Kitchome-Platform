package com.kitchome.auth.service;

import com.kitchome.auth.model.CredentialObject;

import java.util.Optional;

/**
 * Interface defining persistence operations for credentials.
 */
public interface CredentialStorage {
    
    /**
     * Store the credential securely
     * @param path A unique path/key for storage (e.g. "users/1/google")
     * @param credential The credential to store
     */
    void store(String path, CredentialObject credential);
    
    /**
     * Retrieve a stored credential
     * @param path The unique path/key
     * @return Optional containing the credential if found
     */
    Optional<CredentialObject> retrieve(String path);
    
    /**
     * Delete a stored credential
     * @param path The unique path/key
     */
    void delete(String path);
}
