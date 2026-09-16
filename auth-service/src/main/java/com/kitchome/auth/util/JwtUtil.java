package com.kitchome.auth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.function.Function;

@Component
public class JwtUtil {
    @Value("${jwt.expiration-ms:900000}")
    private long expieryDuration;

    private final RsaKeyProvider rsaKeyProvider;

    public JwtUtil(RsaKeyProvider rsaKeyProvider) {
        this.rsaKeyProvider = rsaKeyProvider;
    }

    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimResolver) {
        final Claims cx = extractAllClaims(token);
        return claimResolver.apply(cx);
    }

    public Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    public boolean isExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean isValid(String token, UserDetails user) {
        String userName = extractUsername(token);
        return user.getUsername().equals(userName) && !isExpired(token);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(rsaKeyProvider.getPublicKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setHeaderParam("kid", rsaKeyProvider.getKeyId())
                .setClaims(claims)
                .setSubject(username)
                .setIssuer("kitchome-auth")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expieryDuration))
                .signWith(rsaKeyProvider.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public String generateToken(String username) {
        return generateToken(username, null, "default", "free", List.of("USER"));
    }

    public String generateToken(String username, String email, String tenantId, String tier, List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        if (email != null) {
            claims.put("email", email);
        }
        claims.put("tenant_id", tenantId != null ? tenantId : "default");
        claims.put("tier", tier != null ? tier : "free");
        if (roles != null && !roles.isEmpty()) {
            claims.put("roles", roles);
        }
        return createToken(claims, username);
    }

    public String generateToken(String username, String agentId, List<String> scopes) {
        Map<String, Object> claims = new HashMap<>();
        if (agentId != null) {
            claims.put("agent_id", agentId);
        }
        if (scopes != null && !scopes.isEmpty()) {
            claims.put("scopes", scopes);
        }
        claims.put("tenant_id", "default");
        claims.put("tier", "free");
        return createToken(claims, username);
    }

    public String GenerateTokenWithClaims(Map<String, Object> claims, String username) {
        return createToken(claims, username);
    }
}
