package com.kitchome.auth.integration.provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GoogleCalendarOAuth2ProviderTest {

    @Mock
    private WebClient.Builder webClientBuilder;

    @Mock
    private WebClient webClient;

    @InjectMocks
    private GoogleCalendarOAuth2Provider provider;

    @BeforeEach
    void setUp() {
        when(webClientBuilder.build()).thenReturn(webClient);
        provider = new GoogleCalendarOAuth2Provider(webClientBuilder);

        ReflectionTestUtils.setField(provider, "clientId", "google-client-id");
        ReflectionTestUtils.setField(provider, "clientSecret", "google-client-secret");
    }

    @Test
    void testGetProviderId() {
        assertEquals("google-calendar", provider.getProviderId());
    }

    @Test
    void testGetDisplayName() {
        assertEquals("Google Calendar", provider.getDisplayName());
    }

    @Test
    void testGetDescription() {
        assertEquals("Manage your schedule and events with Google Calendar.", provider.getDescription());
    }

    @Test
    void testGetIconUrl() {
        assertEquals("/500px-Google_Calendar_icon_(2020).svg.png", provider.getIconUrl());
    }

    @Test
    void testGetClientId() {
        assertEquals("google-client-id", provider.getClientId());
    }

    @Test
    void testGetClientSecret() {
        assertEquals("google-client-secret", provider.getClientSecret());
    }

    @Test
    void testGetTokenUri() {
        assertEquals("https://oauth2.googleapis.com/token", provider.getTokenUri());
    }

    @Test
    void testGetAuthorizationEndpoint() {
        assertEquals("https://accounts.google.com/o/oauth2/v2/auth", provider.getAuthorizationEndpoint());
    }

    @Test
    void testGetScopes() {
        assertEquals("https://www.googleapis.com/auth/calendar.readonly", provider.getScopes());
    }
}
