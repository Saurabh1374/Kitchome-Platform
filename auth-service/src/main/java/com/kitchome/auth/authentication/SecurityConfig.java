package com.kitchome.auth.authentication;
/*
 * Author: saurabh sameer
 * Date: 3-03-2025
 * */

import com.kitchome.auth.filters.*;
import com.kitchome.auth.util.JwtUtil;
import com.kitchome.auth.service.CustomOAuth2UserService;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.repository.cdi.Eager;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

/*
 * We are implementing a stateless JWT authentication architecture.
 * Concurrent session tracking and form login mechanics have been deprecated.
 */

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {
	private final UserDetailsService userDetailsService;
	private final JwtUtil jwtUtil;
	private final AccessDeniedHandler customAccessDeniedHandler;
	private final AuthenticationEntryPoint authenticationEntryPoint;
	private final PasswordEncoder passwordEncoder;
	private final com.kitchome.auth.dao.UserRepositoryDao userRepositoryDao;
	private final com.kitchome.auth.service.AuthenticationService authService;
	private final com.kitchome.auth.service.CustomOAuth2UserService customOAuth2UserService;

	@Bean
	public SecurityFilterChain securityHttpConfig(HttpSecurity http) throws Exception {
		http
				.requiresChannel(rcc -> rcc.anyRequest().requiresInsecure())
				.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(
						authz -> authz
								// Allowed public endpoints (New + Legacy + Swagger)
								.requestMatchers("/api/v1/auth/**", "/login", "/register", "/static/**", "/error",
										"/invalidSession", "/", "/verify-email", "/resend-verification",
										"/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html",
										"/*.png", "/*.svg", "/*.jpg", "/*.jpeg", "/*.ico", "/css/**", "/js/**", "/images/**")
								.permitAll()
								.requestMatchers("/api/v1/public", "/api/v1/users/register", "/api/v1/users/login",
										"/api/v1/users/refresh")
								.permitAll() // Legacy
								.requestMatchers(HttpMethod.POST, "/api/v1/users/register", "/api/v1/auth/register")
								.permitAll()
								.requestMatchers(HttpMethod.POST, "/api/v1/users/refresh", "/api/v1/auth/refresh")
								.permitAll()
								.anyRequest().authenticated())
				.csrf(csrf -> csrf.disable())
				.cors(Customizer.withDefaults())
				.addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
				.addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
				.addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class)
				.addFilterBefore(new JwtAuthenticationFilter(jwtUtil, userDetailsService, authenticationEntryPoint),
						UsernamePasswordAuthenticationFilter.class)
				// Resolved: Redundant in stateless auth and caused request hang
				// .addFilterAfter(new AlreadyLoggedInFilter(),JwtAuthenticationFilter.class)
				.oauth2Login(oauth2 -> oauth2
						.userInfoEndpoint(
								userInfo -> userInfo.userService(customOAuth2UserService))
						.successHandler((request, response, authentication) -> {
							Object principal = authentication.getPrincipal();
							if (principal instanceof com.kitchome.auth.authentication.CustomUserDetails) {
								com.kitchome.auth.authentication.CustomUserDetails userDetails = (com.kitchome.auth.authentication.CustomUserDetails) principal;
								if (!userDetails.isEmailVerified()) {
									// Redirect user cleanly so they are denied JWT entry and see the verification message
									response.sendRedirect("/login?unverified_oauth=true");
									return;
								}
							}
							authService.finalizeLogin(request, response, authentication);
							// Redirect to dashboard (tokens are now in HttpOnly cookies!)
							response.sendRedirect("/dashboard");
						}))
				.exceptionHandling(ex -> ex
						.accessDeniedHandler(customAccessDeniedHandler)
						.authenticationEntryPoint(authenticationEntryPoint)// 403
				);
		return http.build();
		// .formLogin(Customizer.withDefaults())
	}



	/*
	 * default authentication provider used
	 * by spring security.
	 *
	 */
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(userDetailsService);
		provider.setPasswordEncoder(passwordEncoder);
		return provider;
	}


	@Bean
	public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
		return http.getSharedObject(AuthenticationManagerBuilder.class)
				.authenticationProvider(authenticationProvider())
				.build();
	}

	/*
	 * it is reccomended to use password encoder factory it provides backward
	 * compatiblity
	 */

	@Bean
	public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource() {
		org.springframework.web.cors.CorsConfiguration configuration = new org.springframework.web.cors.CorsConfiguration();
		// Allow specific origins (adjust as needed for production)
		configuration.setAllowedOrigins(
				java.util.Arrays.asList("http://localhost:5173", "http://localhost:3000", "http://localhost:8080"));
		// Allow all methods
		configuration.setAllowedMethods(java.util.Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		// Allow all headers
		configuration.setAllowedHeaders(java.util.Arrays.asList("*"));
		// Allow credentials (cookies/auth)
		configuration.setAllowCredentials(true);
		// Expose existing Authorization header so frontend can read it
		configuration.setExposedHeaders(java.util.Arrays.asList("Authorization"));

		org.springframework.web.cors.UrlBasedCorsConfigurationSource source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
