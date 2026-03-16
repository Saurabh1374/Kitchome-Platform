package com.kitchome.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A domain object holding credential details in memory. 
 * Has a 1-to-many relationship with CredentialKey handled at the business level.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialObject {
    /** unique identifier (optional, can be null for new credentials) */
    private Long id;
    
    /** owner's ID */
    private Long userId;
    
    /** Credential Type */
    private CredentialType type;
    
    /** ID of the CredentialProvider responsible for lifecycle management */
    private String providerId;
    
    /** Contains the actual secrets */
    @Builder.Default
    private List<CredentialKey> keys = new ArrayList<>();
    
    /** expiration timestamp in epoch seconds (e.g. valid until this unix timestamp) */
    private Long expiresAt;
    
    /** non-secret connection metadata */
    @Builder.Default
    private Map<String, String> metadata = new HashMap<>();

    public void addKey(CredentialKey key) {
        if (keys == null) {
            keys = new ArrayList<>();
        }
        keys.removeIf(k -> k.getKeyName().equals(key.getKeyName())); // replace if exists
        keys.add(key);
    }
    
    public void addKey(String keyName, String keyValue) {
        addKey(CredentialKey.builder().keyName(keyName).keyValue(keyValue).build());
    }

    public Optional<CredentialKey> getKey(String keyName) {
        if (keys == null) return Optional.empty();
        return keys.stream()
                .filter(k -> k.getKeyName().equals(keyName))
                .findFirst();
    }
    
    public Optional<String> getKeyValue(String keyName) {
        return getKey(keyName).map(CredentialKey::getKeyValue);
    }
    
    public boolean hasAnyKeys() {
        return keys != null && !keys.isEmpty();
    }
}
