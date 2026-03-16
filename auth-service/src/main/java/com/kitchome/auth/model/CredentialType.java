package com.kitchome.auth.model;

/**
 * Types of credentials the store can manage.
 */
public enum CredentialType {
    /** Simple API key (e.g., Brave Search, OpenAI) */
    API_KEY("api_key"),

    /** OAuth2 with refresh token support */
    OAUTH2("oauth2"),

    /** Username/password pair */
    BASIC_AUTH("basic_auth"),

    /** JWT or bearer token without refresh */
    BEARER_TOKEN("bearer_token"),

    /** User-defined credential type */
    CUSTOM("custom");

    private final String value;

    CredentialType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
