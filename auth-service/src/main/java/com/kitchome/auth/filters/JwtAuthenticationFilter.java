package com.kitchome.auth.filters;

import com.kitchome.auth.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.annotations.Filter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

@Slf4j
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.info("jwt checking");
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String jwt = authHeader.substring(7);
                String username = jwtUtil.extractUsername(jwt);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    // Extract agent_id from token
                    String agentId = jwtUtil.extractClaims(jwt, claims -> claims.get("agent_id", String.class));

                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    if (jwtUtil.isValid(jwt, userDetails)) {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());

                        // Add agent_id to details if present
                        if (agentId != null) {
                            Map<String, Object> details = new HashMap<>();
                            details.put("agent_id", agentId);
                            authToken.setDetails(details);
                            log.debug("Authenticated agent: {}", agentId);
                        } else {
                            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        }

                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            }
            filterChain.doFilter(request, response);
        } catch (JwtException | UsernameNotFoundException ex) {
            authenticationEntryPoint.commence(request, response,
                    new AuthenticationException("Invalid or expired JWT") {
                    });
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        String method = request.getMethod();

        // Skip JWT filter for refresh endpoint (Legacy & New)
        return ("/api/v1/users/refresh".equals(path) || "/api/v1/auth/refresh".equals(path))
                && "POST".equalsIgnoreCase(method);
    }
}
