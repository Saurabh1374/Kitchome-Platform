package com.kitchome.auth.integration.provider;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class GoogleCalendarOAuth2Provider extends GenericOAuth2Provider {

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    public GoogleCalendarOAuth2Provider(WebClient.Builder webClientBuilder) {
        super(webClientBuilder);
    }

    @Override
    public String getProviderId() {
        return "google-calendar";
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
        return "https://oauth2.googleapis.com/token";
    }

    @Override
    protected String getAuthorizationEndpoint() {
        return "https://accounts.google.com/o/oauth2/v2/auth";
    }

    @Override
    protected String getScopes() {
        return "https://www.googleapis.com/auth/calendar.readonly";
    }
}
