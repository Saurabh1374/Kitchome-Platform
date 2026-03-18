package com.kitchome.auth.integration.provider;

import com.kitchome.auth.model.CredentialObject;
import com.kitchome.auth.model.CredentialType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class GenericOAuth2ProviderTest {

    private ExchangeFunction exchangeFunction;
    private DummyOAuth2Provider provider;

    private static class DummyOAuth2Provider extends GenericOAuth2Provider {
        public DummyOAuth2Provider(WebClient.Builder builder) {
            super(builder);
        }

        @Override
        public String getProviderId() {
            return "dummy";
        }

        @Override
        protected String getClientId() {
            return "dummy-client";
        }

        @Override
        protected String getClientSecret() {
            return "dummy-secret";
        }

        @Override
        protected String getTokenUri() {
            return "https://dummy.com/token";
        }

        @Override
        protected String getAuthorizationEndpoint() {
            return "https://dummy.com/auth";
        }

        @Override
        protected String getScopes() {
            return "read write";
        }
    }

    @BeforeEach
    void setUp() {
        exchangeFunction = mock(ExchangeFunction.class);
        WebClient.Builder builder = WebClient.builder().exchangeFunction(exchangeFunction);
        provider = new DummyOAuth2Provider(builder);
    }

    @Test
    void testGetSupportedTypes() {
        assertTrue(provider.getSupportedTypes().contains(CredentialType.OAUTH2));
    }

    @Test
    void testGetAuthorizationUrl() {
        String url = provider.getAuthorizationUrl("state123", "https://redirect.com");
        String expected = "https://dummy.com/auth?client_id=dummy-client&redirect_uri=https://redirect.com&response_type=code&state=state123&scope=read write&access_type=offline&prompt=consent";
        assertEquals(expected, url);
    }

    @Test
    void testExchangeCodeForTokens() {
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("access_token", "access123");
        responseMap.put("refresh_token", "refresh123");

        ClientResponse response = ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", "application/json")
                .body("{\"access_token\":\"access123\",\"refresh_token\":\"refresh123\"}")
                .build();

        when(exchangeFunction.exchange(any(ClientRequest.class))).thenReturn(Mono.just(response));

        Map<String, Object> result = provider.exchangeCodeForTokens("code123", "https://redirect.com").block();
        assertNotNull(result);
        assertEquals("access123", result.get("access_token"));
        assertEquals("refresh123", result.get("refresh_token"));
    }

    @Test
    void testValidateAndShouldRefresh() {
        CredentialObject cred = new CredentialObject(); // no keys
        assertFalse(provider.validate(cred));

        cred.addKey("access_token", "token");
        // No expiration -> considered valid if access_token exists
        assertTrue(provider.validate(cred));

        // Expires in past
        cred.setExpiresAt(Instant.now().getEpochSecond() - 3600);
        assertFalse(provider.validate(cred));

        // Expires in future
        cred.setExpiresAt(Instant.now().getEpochSecond() + 3600);
        assertTrue(provider.validate(cred));

        // Should refresh check
        cred.setExpiresAt(Instant.now().getEpochSecond() - 3600);
        cred.addKey("refresh_token", "refresh");
        assertTrue(provider.shouldRefresh(cred));
    }

    @Test
    void testRefresh() {
        CredentialObject cred = new CredentialObject();
        cred.addKey("refresh_token", "old-refresh");

        ClientResponse response = ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", "application/json")
                .body("{\"access_token\":\"new-access\",\"expires_in\":3600}")
                .build();

        when(exchangeFunction.exchange(any(ClientRequest.class))).thenReturn(Mono.just(response));

        CredentialObject result = provider.refresh(cred).block();
        assertNotNull(result);
        assertEquals("new-access", result.getKeyValue("access_token").orElse(null));
        assertTrue(result.getExpiresAt() > Instant.now().getEpochSecond());
    }

    @Test
    void testRefresh_NoRefreshToken() {
        CredentialObject cred = new CredentialObject(); // no refresh token

        assertThrows(IllegalStateException.class, () -> provider.refresh(cred).block());
    }
}
