package com.kitchome.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A domain object representing a single key-value pair for a credential.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialKey {
    /** The name of the key (e.g., "access_token", "refresh_token", "api_key") */
    private String keyName;
    
    /** The actual secret value */
    private String keyValue;
    
    /** Optional metadata about the key */
    private String type;
}
