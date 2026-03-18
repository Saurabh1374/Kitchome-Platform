package com.kitchome.auth.filters;

import com.kitchome.auth.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import com.kitchome.auth.authentication.CustomUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import jakarta.servlet.http.Cookie;

@Slf4j
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        log.info("jwt checking");

        String jwt = null;
        String username = null;

        try {
            // 1. Try to get JWT from cookies
            if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if ("jwt".equals(cookie.getName())) {
                        jwt = cookie.getValue();
                        log.debug("JWT found in cookie.");
                        break;
                    }
                }
            }

            // 2. If not in cookies, try to get JWT from Authorization header
            if (jwt == null) {
                String authorizationHeader = request.getHeader("Authorization");
                if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                    jwt = authorizationHeader.substring(7);
                    log.debug("JWT found in Authorization header.");
                }
            }

            // 3. If not in header, try to get JWT from request parameter
            if (jwt == null) {
                jwt = request.getParameter("jwt");
                if (jwt != null) {
                    log.debug("JWT found in request parameter.");
                }
            }

            if (jwt != null) {
                username = jwtUtil.extractUsername(jwt);
                log.debug("Extracted username: {}", username);
            }

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                if (jwtUtil.isValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

                    Map<String, Object> details = new HashMap<>();
                    details.put("webAuthenticationDetails", new WebAuthenticationDetailsSource().buildDetails(request));

                    // Check for agent_id in the token and add to details
                    String agentId = jwtUtil.extractClaims(jwt, claims -> claims.get("agent_id", String.class));
                    if (agentId != null) {
                        details.put("agent_id", agentId);
                        log.debug("Agent ID {} found in JWT and added to authentication details.", agentId);
                    }

                    usernamePasswordAuthenticationToken.setDetails(details);
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    log.info("User {} authenticated successfully.", username);
                } else {
                    log.warn("JWT token for user {} is invalid.", username);
                }
            }

            // 4. Verification Guard logic
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof CustomUserDetails) {
                CustomUserDetails user = (CustomUserDetails) auth.getPrincipal();

                String path = request.getServletPath();
                // If user is authenticated but NOT verified, restrict access
                if (!user.isEmailVerified()) {
                    // Allowed paths for unverified users
                    boolean isAllowedPath = path.equals("/verify-email") ||
                            path.equals("/api/v1/auth/resend-verification") ||
                            path.equals("/api/v1/auth/logout") ||
                            path.startsWith("/css/") ||
                            path.startsWith("/js/") ||
                            path.startsWith("/images/") ||
                            path.startsWith("/static/");

                    if (!isAllowedPath) {
                        log.info("Unverified user {} attempted to access {}. Redirecting to /verify-email",
                                user.getUsername(), path);
                        response.sendRedirect("/verify-email");
                        return;
                    }
                }
            }

        } catch (JwtException e) {
            log.warn("JWT validation failed: {}", e.getMessage());
            authenticationEntryPoint.commence(request, response, new AuthenticationException("Invalid JWT token", e) {
            });
            return; // Stop further processing if JWT is invalid
        } catch (UsernameNotFoundException e) {
            log.warn("User not found for username extracted from JWT: {}", username);
            // Clear the invalid cookie
            Cookie cookie = new Cookie("jwt", null);
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            cookie.setMaxAge(0);
            response.addCookie(cookie);
            
            response.sendRedirect("/");
            return; // Stop further processing
        } catch (AuthenticationException e) {
            log.warn("Authentication failed: {}", e.getMessage());
            authenticationEntryPoint.commence(request, response, e);
            return; // Stop further processing if authentication fails
        }

        filterChain.doFilter(request, response);
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
