package com.kitchome.auth.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

@Component
public class RsaKeyProvider {
    private static final Logger log = LoggerFactory.getLogger(RsaKeyProvider.class);
    public static final String KEY_ID = "kitchome-auth-key-1";

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
    private JWKSet jwkSet;

    @PostConstruct
    public void init() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            this.publicKey = (RSAPublicKey) keyPair.getPublic();
            this.privateKey = (RSAPrivateKey) keyPair.getPrivate();

            RSAKey rsaKey = new RSAKey.Builder(this.publicKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID(KEY_ID)
                    .build();

            this.jwkSet = new JWKSet(rsaKey);
            log.info("Successfully initialized RSA 2048 KeyPair with kid: {}", KEY_ID);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to initialize RSA key pair", e);
        }
    }

    public String getKeyId() {
        return KEY_ID;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public Map<String, Object> getJwkSetJson() {
        return jwkSet.toJSONObject();
    }
}
