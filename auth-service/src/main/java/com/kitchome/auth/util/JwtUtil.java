package com.kitchome.auth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.function.Function;

@Component
public class JwtUtil {
    @Value("${jwt.secret}")
    private String SECRET;
    @Value("${jwt.expiration-ms}")
    private long expieryDuration;

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
        return user.getUsername().equals(extractUsername(token)) && !isExpired(token);

    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(getSigningkey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expieryDuration))
                .signWith(getSigningkey(), SignatureAlgorithm.HS256).compact();
    }

    public String generateToken(String username) {
        return generateToken(username, null, null);
    }

    public String generateToken(String username, String agentId, List<String> scopes) {
        Map<String, Object> claims = new HashMap<>();
        if (agentId != null) {
            claims.put("agent_id", agentId);
        }
        if (scopes != null && !scopes.isEmpty()) {
            claims.put("scopes", scopes);
        }
        return createToken(claims, username);
    }

    public String GenerateTokenWithClaims(Map<String, Object> claims, String username) {
        return createToken(claims, username);
    }

    private Key getSigningkey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
