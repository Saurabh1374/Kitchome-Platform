package com.kitchome.auth.service;

import com.kitchome.auth.integration.CredentialProvider;
import com.kitchome.auth.model.CredentialObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

@Slf4j
@Service
public class CredentialLifecycleManager {

    private final CredentialStorage credentialStorage;
    private final List<CredentialProvider> providers;
    
    @Value("${app.credentials.path-format:secret/users/%s/%s}")
    private String pathFormat;

    private final ConcurrentHashMap<String, ReentrantLock> refreshLocks = new ConcurrentHashMap<>();

    public CredentialLifecycleManager(CredentialStorage credentialStorage, List<CredentialProvider> providers) {
        this.credentialStorage = credentialStorage;
        this.providers = providers;
    }

    public List<CredentialProvider> getProviders() {
        return providers;
    }

    public Mono<CredentialObject> getValidCredential(String userId, String providerId) {
        String path = String.format(pathFormat, userId, providerId);

        return Mono.fromCallable(() -> credentialStorage.retrieve(path))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(optCred -> optCred
                        .map(Mono::just)
                        .orElseGet(() -> Mono.error(new RuntimeException("Credential not found for path: " + path))))
                .flatMap(credential -> {
                    CredentialProvider provider = findProvider(providerId);

                    if (provider.shouldRefresh(credential)) {
                        log.info("Credential for {} needs refresh. Attempting refresh asynchronously.", providerId);
                        
                        // We use a ReentrantLock mapped by path to ensure thread safety
                        // preventing concurrent token refreshes that could invalidate tokens.
                        ReentrantLock lock = refreshLocks.computeIfAbsent(path, k -> new ReentrantLock());
                        
                        return Mono.using(
                                () -> {
                                    lock.lock();
                                    return lock;
                                },
                                l -> provider.refresh(credential)
                                        .flatMap(updatedCred -> 
                                            Mono.fromRunnable(() -> credentialStorage.store(path, updatedCred))
                                                .subscribeOn(Schedulers.boundedElastic())
                                                .thenReturn(updatedCred)
                                        ),
                                ReentrantLock::unlock
                        ).subscribeOn(Schedulers.boundedElastic());
                    }

                    if (!provider.validate(credential)) {
                        return Mono.error(new RuntimeException("Credential is invalid and cannot be refreshed."));
                    }

                    return Mono.just(credential);
                });
    }

    public CredentialProvider findProvider(String providerId) {
        return providers.stream()
                .filter(p -> p.getProviderId().equalsIgnoreCase(providerId))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No CredentialProvider found for: " + providerId));
    }
    
    public void storeCredential(String userId, String providerId, CredentialObject credential) {
        String path = String.format(pathFormat, userId, providerId);
        credential.setUserId(Long.parseLong(userId));
        credential.setProviderId(providerId);
        credentialStorage.store(path, credential);
    }
}
