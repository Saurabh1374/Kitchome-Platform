package com.kitchome.auth.service;

import com.kitchome.auth.config.ApplicationConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import com.kitchome.auth.util.JwtUtil;
import com.kitchome.auth.integration.CredentialProvider;
import com.kitchome.auth.model.CredentialObject;
import com.kitchome.auth.model.CredentialType;

import com.kitchome.auth.payload.IntegrationInfoDTO;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.entity.IntegrationMetadata;
import com.kitchome.auth.dao.IntegrationMetadataRepository;
import com.kitchome.auth.dao.UserRepositoryDao;
import java.time.Instant;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ThirdPartyIntegrationService {

    // private final ApplicationConfig applicationConfig;
    private final CredentialLifecycleManager credentialLifecycleManager;
    private final IntegrationMetadataRepository integrationMetadataRepository;
    private final UserRepositoryDao userRepository;
    private final JwtUtil jwtUtil;

    /**
     * Link a user to a provider using an authorization code.
     */
    public Mono<Void> linkUserToProvider(String username, String serviceName, String code, String redirectUri) {
        CredentialProvider provider = credentialLifecycleManager.findProvider(serviceName);
        return Mono.fromCallable(() -> userRepository.findByUsername(username))
                .subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic())
                .flatMap(Mono::justOrEmpty)
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")))
                .flatMap(user -> provider.exchangeCodeForTokens(code, redirectUri)
                        .flatMap(tokens -> {
                            CredentialObject credential = new CredentialObject();
                            credential.setType(CredentialType.OAUTH2);
                            credential.setUserId(user.getId());
                            credential.setProviderId(serviceName);

                            if (tokens.containsKey("access_token")) {
                                credential.addKey("access_token", (String) tokens.get("access_token"));
                            }
                            if (tokens.containsKey("refresh_token")) {
                                credential.addKey("refresh_token", (String) tokens.get("refresh_token"));
                            }
                            if (tokens.containsKey("expires_in")) {
                                long expiresIn = ((Number) tokens.get("expires_in")).longValue();
                                credential.setExpiresAt(Instant.now().getEpochSecond() + expiresIn);
                            } else if (tokens.containsKey("expires_at")) {
                                credential.setExpiresAt(Long.parseLong(tokens.get("expires_at").toString()));
                            }

                            // 1. Reactive boundary for storing credentials
                            Mono<Object> saveCredentialMono = Mono.fromCallable(() -> {
                                credentialLifecycleManager.storeCredential(user.getId().toString(), serviceName,
                                        credential);
                                return new Object();
                            }).subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic());

                            // 2. Reactive boundary for persisting metadata
                            Mono<Object> saveMetadataMono = Mono.fromCallable(
                                    () -> integrationMetadataRepository.findByServiceNameAndUser(serviceName, user))
                                    .subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic())
                                    .flatMap(existing -> {
                                        if (existing.isEmpty()) {
                                            IntegrationMetadata metadata = IntegrationMetadata.builder()
                                                    .serviceName(serviceName)
                                                    .vaultPath(serviceName)
                                                    .user(user)
                                                    .build();
                                            return Mono.fromCallable(() -> integrationMetadataRepository.save(metadata))
                                                    .subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic());
                                        }
                                        return Mono.empty();
                                    });

                            // Guarantee strict sequential execution and error tracking
                            return saveCredentialMono.then(saveMetadataMono).then();
                        }));
    }

    /**
     * Get a valid access token for a user, refreshing if necessary, and return as
     * signed payload.
     */
    public Mono<String> getSignedAccessKey(String username, String serviceName) {
        return Mono.fromCallable(() -> userRepository.findByUsername(username))
                .subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic())
                .flatMap(Mono::justOrEmpty)
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")))
                .flatMap(user -> credentialLifecycleManager.getValidCredential(user.getId().toString(), serviceName))
                .switchIfEmpty(Mono.error(new com.kitchome.auth.Exception.AuthException(
                        com.kitchome.auth.util.ErrorCode.TOKEN_NOT_FOUND)))
                .map(credential -> {
                    String activeKey = credential.getKeyValue("access_token").orElseThrow(
                            () -> new IllegalStateException("Access token missing in credential"));
                    Map<String, Object> claims = new HashMap<>();
                    claims.put("service", serviceName);
                    claims.put("key", activeKey);
                    return jwtUtil.GenerateTokenWithClaims(claims, username);
                });
    }

    public String getAuthorizationLink(String serviceName, String username) {
        // state ideally should be a secure hash, simple username works for demo.
        String state = username;
        String redirectUri = String.format("http://localhost:8080/api/v1/auth/integrations/%s/callback", serviceName);
        CredentialProvider provider = credentialLifecycleManager.findProvider(serviceName);
        return provider.getAuthorizationUrl(state, redirectUri);
    }

    /**
     * Get a list of all available integrations and whether they are connected for
     * the user.
     */
    public List<IntegrationInfoDTO> getAvailableIntegrations(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<String> connectedServices = integrationMetadataRepository.findByUser(user).stream()
                .map(IntegrationMetadata::getServiceName)
                .collect(Collectors.toList());

        return credentialLifecycleManager.getProviders().stream()
                .filter(p -> !(p instanceof com.kitchome.auth.integration.provider.BearerTokenProvider)) // Filter out
                                                                                                         // internal
                                                                                                         // providers if
                                                                                                         // any
                .map(provider -> IntegrationInfoDTO.builder()
                        .name(provider.getProviderId())
                        .displayName(provider.getDisplayName())
                        .description(provider.getDescription())
                        .iconUrl(provider.getIconUrl())
                        .connected(connectedServices.contains(provider.getProviderId()))
                        .build())
                .collect(Collectors.toList());
    }
}
