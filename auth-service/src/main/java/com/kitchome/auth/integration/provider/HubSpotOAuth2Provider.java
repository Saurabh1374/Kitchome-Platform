package com.kitchome.auth.integration.provider;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * HubSpot-specific OAuth2 provider.
 */
@Component
public class HubSpotOAuth2Provider extends GenericOAuth2Provider {

    @Value("${hubspot.client.id:default-client-id}")
    private String clientId;

    @Value("${hubspot.client.secret:default-secret}")
    private String clientSecret;

    public HubSpotOAuth2Provider(WebClient.Builder webClientBuilder) {
        super(webClientBuilder);
    }

    @Override
    public String getProviderId() {
        return "hubspot";
    }

    @Override
    public String getDisplayName() {
        return "HubSpot";
    }

    @Override
    public String getDescription() {
        return "Sync your contacts and deals with HubSpot CRM.";
    }

    @Override
    public String getIconUrl() {
        return "https://cdn-icons-png.flaticon.com/512/732/732213.png"; // HubSpot icon
    }

    @Override
    protected String getClientId() {
        return clientId;
    }

    @Override
    protected String getClientSecret() {
        return clientSecret;
    }

    @Override
    protected String getTokenUri() {
        return "https://api.hubapi.com/oauth/v1/token";
    }
}
