package com.kitchome.auth.filters;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import lombok.extern.slf4j.Slf4j;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import
// org.springframework.security.web.authentication.AuthenticationSuccessHandler;
// import org.springframework.web.filter.OncePerRequestFilter;

// import java.io.IOException;
// @Slf4j
/*
 * DEPRECATED: This filter is redundant in a stateless JWT architecture and
 * contained a bug
 * where it would terminate requests without a response.
 *
 * It has been removed from the SecurityConfig chain.
 * Retaining file for historical reference as per project policy.
 *
 * public class AlreadyLoggedInFilter extends OncePerRequestFilter {
 * 
 * public AlreadyLoggedInFilter() {
 * }
 * 
 * @Override
 * protected void doFilterInternal(HttpServletRequest request,
 * HttpServletResponse response, FilterChain filterChain) throws
 * ServletException, IOException {
 * String path = request.getRequestURI();
 * log.info(path);
 * if ("/api/v1/users/login".equals(path)) {
 * Authentication auth = SecurityContextHolder.getContext().getAuthentication();
 * 
 * if (auth != null && auth.isAuthenticated() &&
 * !"anonymousUser".equals(auth.getPrincipal())) {
 * log.info("already logged in");
 * // ✅ Already authenticated → delegate to success handler
 * log.info("call from filter");
 * return;
 * }
 * }
 * filterChain.doFilter(request, response);
 * }
 * 
 * 
 * }
 */
