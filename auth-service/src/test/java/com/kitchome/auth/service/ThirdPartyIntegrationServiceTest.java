package com.kitchome.auth.service;

import com.kitchome.auth.config.ApplicationConfig;
import com.kitchome.auth.dao.IntegrationMetadataRepository;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.entity.IntegrationMetadata;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.integration.CredentialProvider;
import com.kitchome.auth.model.CredentialObject;
import com.kitchome.auth.payload.IntegrationInfoDTO;
import com.kitchome.auth.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ThirdPartyIntegrationServiceTest {

    @Mock
    private ApplicationConfig applicationConfig;
    @Mock
    private CredentialLifecycleManager credentialLifecycleManager;
    @Mock
    private IntegrationMetadataRepository integrationMetadataRepository;
    @Mock
    private UserRepositoryDao userRepository;
    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private CredentialProvider credentialProvider;

    @InjectMocks
    private ThirdPartyIntegrationService service;

    private User mockUser;

    @BeforeEach
    void setUp() {
        mockUser = new User();
        mockUser.setId(1L);
        mockUser.setUsername("testuser");
    }

    @Test
    void testLinkUserToProvider_Success_WithNewMetadata() {
        String serviceName = "google";
        String code = "authcode";
        String redirectUri = "http://redir";

        when(credentialLifecycleManager.findProvider(serviceName)).thenReturn(credentialProvider);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(mockUser));

        Map<String, Object> tokens = new HashMap<>();
        tokens.put("access_token", "accToken");
        tokens.put("refresh_token", "refToken");
        tokens.put("expires_in", 3600);
        when(credentialProvider.exchangeCodeForTokens(code, redirectUri)).thenReturn(Mono.just(tokens));

        when(integrationMetadataRepository.findByServiceNameAndUser(serviceName, mockUser))
                .thenReturn(Optional.empty());
        when(integrationMetadataRepository.save(any(IntegrationMetadata.class))).thenReturn(new IntegrationMetadata());

        Mono<Void> result = service.linkUserToProvider("testuser", serviceName, code, redirectUri);

        result.block();

        verify(credentialLifecycleManager).storeCredential(eq("1"), eq(serviceName), any(CredentialObject.class));
        verify(integrationMetadataRepository).save(any(IntegrationMetadata.class));
    }

    @Test
    void testLinkUserToProvider_UserNotFound() {
        when(credentialLifecycleManager.findProvider("google")).thenReturn(credentialProvider);
        when(userRepository.findByUsername("unknown")).thenReturn(Optional.empty());

        Mono<Void> result = service.linkUserToProvider("unknown", "google", "code", "uri");

        RuntimeException ex = assertThrows(RuntimeException.class, () -> result.block());
        assertTrue(ex.getMessage().contains("User not found") || ex.getCause().getMessage().contains("User not found"));
    }

    @Test
    void testGetSignedAccessKey_Success() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(mockUser));

        CredentialObject cred = new CredentialObject();
        cred.addKey("access_token", "validAccess");

        when(credentialLifecycleManager.getValidCredential("1", "google")).thenReturn(Mono.just(cred));
        when(jwtUtil.GenerateTokenWithClaims(anyMap(), eq("testuser"))).thenReturn("signed.jwt.token");

        Mono<String> result = service.getSignedAccessKey("testuser", "google");

        assertEquals("signed.jwt.token", result.block());
    }

    @Test
    void testGetSignedAccessKey_MissingToken() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(mockUser));

        CredentialObject cred = new CredentialObject(); // no access_token
        when(credentialLifecycleManager.getValidCredential("1", "google")).thenReturn(Mono.just(cred));

        Mono<String> result = service.getSignedAccessKey("testuser", "google");

        assertThrows(Exception.class, () -> result.block());
    }

    @Test
    void testGetSignedAccessKey_CredentialNotFound() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(mockUser));

        when(credentialLifecycleManager.getValidCredential("1", "google")).thenReturn(Mono.empty());

        Mono<String> result = service.getSignedAccessKey("testuser", "google");

        assertThrows(Exception.class, () -> result.block());
    }

    @Test
    void testGetAuthorizationLink() {
        when(credentialLifecycleManager.findProvider("google")).thenReturn(credentialProvider);
        when(credentialProvider.getAuthorizationUrl(eq("testuser"), anyString())).thenReturn("http://auth.url");

        String link = service.getAuthorizationLink("google", "testuser");
        assertEquals("http://auth.url", link);
    }

    @Test
    void testGetAvailableIntegrations() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(mockUser));

        IntegrationMetadata meta = IntegrationMetadata.builder().serviceName("google").build();
        when(integrationMetadataRepository.findByUser(mockUser)).thenReturn(List.of(meta));

        CredentialProvider mockProvider1 = mock(CredentialProvider.class);
        when(mockProvider1.getProviderId()).thenReturn("google");
        when(mockProvider1.getDisplayName()).thenReturn("Google");

        CredentialProvider mockProvider2 = mock(CredentialProvider.class);
        when(mockProvider2.getProviderId()).thenReturn("github");
        when(mockProvider2.getDisplayName()).thenReturn("GitHub");

        when(credentialLifecycleManager.getProviders()).thenReturn(List.of(mockProvider1, mockProvider2));

        List<IntegrationInfoDTO> result = service.getAvailableIntegrations("testuser");

        assertEquals(2, result.size());

        IntegrationInfoDTO gInfo = result.stream().filter(i -> i.getName().equals("google")).findFirst().get();
        assertTrue(gInfo.isConnected());

        IntegrationInfoDTO ghInfo = result.stream().filter(i -> i.getName().equals("github")).findFirst().get();
        assertFalse(ghInfo.isConnected());
    }

    @Test
    void testGetAvailableIntegrations_UserNotFound() {
        when(userRepository.findByUsername("unknown")).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> service.getAvailableIntegrations("unknown"));
    }
}
