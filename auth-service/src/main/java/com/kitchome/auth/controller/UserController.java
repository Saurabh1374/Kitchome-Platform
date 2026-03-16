package com.kitchome.auth.controller;

import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

import com.kitchome.auth.Exception.AuthException;
import com.kitchome.auth.authentication.CustomUserDetails;
import com.kitchome.auth.authentication.UserCredentials;
import com.kitchome.auth.entity.RefreshToken;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.payload.*;
import com.kitchome.auth.payload.projection.UserCredProjection;
import com.kitchome.auth.service.RefreshTokenService;
import com.kitchome.auth.util.ErrorCode;
import com.kitchome.auth.util.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jdk.jfr.ContentType;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.kitchome.common.exception.ValidationException;
import com.kitchome.common.payload.ApiResponse;
import com.kitchome.auth.service.UserService;

@Slf4j
@Controller
@RequestMapping("api/v1/users")
/**
 * @deprecated
 *             This controller has been refactored into two separate components:
 *             1. {@link com.kitchome.auth.controller.AuthRestController} -
 *             Logic/API (JSON)
 *             2. {@link com.kitchome.auth.controller.AuthViewController} -
 *             UI/Views (Thymeleaf)
 *
 *             Please use the new components. This class is retained for
 *             backward compatibility details.
 */
@Deprecated
public class UserController {
	private final UserCredentials userService;
	private final AuthenticationManager authenticationManager;
	private final JwtUtil jwtUtil;
	private final RefreshTokenService refreshTokenService;
	private final AuthenticationSuccessHandler successHandler;

	public UserController(UserCredentials userService, AuthenticationManager authenticationManager, JwtUtil jwtUtil,
			RefreshTokenService refreshTokenService, AuthenticationSuccessHandler successHandler) {
		super();
		this.userService = userService;
		this.authenticationManager = authenticationManager;
		this.jwtUtil = jwtUtil;
		this.refreshTokenService = refreshTokenService;
		this.successHandler = successHandler;
	}

	@GetMapping("/register")
	public String showRegistrationForm() {
		return "register"; // This will look for register.html in resources/templates
	}

	@PostMapping("/register")
	public ResponseEntity<?> createUser(@RequestBody @Valid RegisterUserDTO userDto) {
		try {
			userService.registerUser(userDto);
			return ResponseEntity
					.status(HttpStatus.CREATED)
					.body("User registered successfully");
		} catch (Exception ve) {
			throw new AuthException(ErrorCode.USER_ALREADY_AVAILABLE, ve.getMessage());
		}
	}

	@PostMapping("/login")

	public ResponseEntity<?> login(@RequestBody AuthRequestDTO request,
			HttpServletRequest httpRequest, HttpServletResponse response) {
		// Refactored: Removed check for existing token to allow re-login/account switch
		// 1. Authenticate user
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

		UserDetails user = (UserDetails) authentication.getPrincipal();

		// 2. Generate JWT token
		String accessToken = jwtUtil.generateToken(user.getUsername());

		// 3. Extract fingerprint & IP
		String fingerprint = getFingerprint(httpRequest);
		String ip = httpRequest.getRemoteAddr();
		String userAgent = httpRequest.getHeader("User-Agent");
		// add header

		// fix credential leak
		// 4. Generate Refresh Token
		RefreshToken refreshToken = refreshTokenService
				.generateAndStoreRefreshToken(user.getUsername(), fingerprint, ip, userAgent);
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);

		// Refactored to use ResponseCookie for SameSite=Strict protection against CSRF
		org.springframework.http.ResponseCookie refreshCookie = org.springframework.http.ResponseCookie
				.from("refreshToken", refreshToken.getToken())
				.httpOnly(true)
				.secure(false) // TODO: Set to true in production
				.path("/")
				.maxAge(15 * 24 * 60 * 60)
				.sameSite("Strict")
				.build();

		response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

		return ResponseEntity.status(HttpStatus.OK).headers(headers)
				.body(new JwtResponseDTO(accessToken, refreshToken.getToken()));
	}

	/*
	 * Semantics of HTTP
	 * 
	 * GET is meant to be safe and idempotent (shouldn’t change server state).
	 * 
	 * Refreshing a token does change server state (old refresh invalidated, new one
	 * issued).
	 * 
	 * So using GET breaks REST principles.
	 * 
	 * Caching Issues
	 * 
	 * Browsers, proxies, CDNs may cache GET responses.
	 * 
	 * You do not want access tokens cached or accidentally replayed.
	 * 
	 * Security
	 * 
	 * GET params can leak in logs, browser history, referrers if you ever put
	 * tokens in the query string (bad idea).
	 * 
	 * Even though here you’re using cookies/localStorage, attackers may exploit the
	 * assumption that GET = cacheable.
	 */
	@PostMapping("/refresh")
	public ResponseEntity<JwtResponseDTO> refreshToken(HttpServletRequest httpRequest, HttpServletResponse response) {
		try {
			String rawToken = Arrays.stream(Optional.ofNullable(httpRequest.getCookies()).orElse(new Cookie[0]))
					.filter(c -> "refreshToken".equals(c.getName()))
					.map(Cookie::getValue)
					.findFirst()
					.orElseThrow(() -> new AuthException(ErrorCode.TOKEN_NOT_FOUND));
			String fingerprint = getFingerprint(httpRequest);
			String ip = httpRequest.getRemoteAddr();

			RefreshToken token = refreshTokenService.validate(rawToken);

			// Optional: verify fingerprint/ip/userAgent matches
			if (!token.getFingerprint().equals(fingerprint) || !token.getIp().equals(ip)) {
				throw new AuthException(ErrorCode.SUSPESIOUS);
			}

			refreshTokenService.invalidate(token); // rotation

			User user = token.getUser();
			String newAccessToken = jwtUtil.generateToken(user.getUsername());
			RefreshToken newRefresh = refreshTokenService
					.generateAndStoreRefreshToken(user.getUsername(), fingerprint, ip,
							httpRequest.getHeader("User-Agent"));
			HttpHeaders headers = new HttpHeaders();
			headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + newAccessToken);

			// Refactored to use ResponseCookie for SameSite=Strict protection against CSRF
			org.springframework.http.ResponseCookie refreshCookie = org.springframework.http.ResponseCookie
					.from("refreshToken", newRefresh.getToken())
					.httpOnly(true)
					.secure(false) // TODO: Set to true in production
					.path("/")
					.maxAge(15 * 24 * 60 * 60)
					.sameSite("Strict")
					.build();

			response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

			return ResponseEntity.status(HttpStatus.OK).headers(headers)
					.body(new JwtResponseDTO(newAccessToken, newRefresh.getToken()));
		} catch (AuthException ae) {
			log.error("Failed request", ae);
			throw new AuthException(ErrorCode.INTERNAL_SERVER_ERROR, ae);
		}
	}

	@GetMapping("/dashboard")
	public String dashboard(Model model) throws BadRequestException {
		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null || !principal.isAuthenticated() || principal instanceof AnonymousAuthenticationToken) {
			throw new BadRequestException("Bad credentials");
		}
		String username = principal.getName();

		// Example: Get role from Authentication
		// Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		String role = principal.getAuthorities() != null
				? principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
						.collect(Collectors.joining(", "))
				: "N/A";
		CustomUserDetails pass = (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication()
				.getPrincipal();
		String today = LocalDate.now().format(DateTimeFormatter.ofPattern("MMMM dd, yyyy"));

		model.addAttribute("username", username);
		model.addAttribute("role", role);
		model.addAttribute("pass", pass.getPassword());
		model.addAttribute("today", today);

		return "dashboard";
	}

	@GetMapping("/login")
	public String loginPage() {
		return "login"; // resolves to login.html or login.jsp based on your view setup
	}

	private String getFingerprint(HttpServletRequest request) {
		// Prefer header or cookie
		String fingerprint = request.getHeader("X-Device-Fingerprint");
		if (fingerprint == null) {
			Cookie[] cookies = request.getCookies();
			if (cookies != null) {
				for (Cookie c : cookies) {
					if ("fingerprint".equals(c.getName())) {
						return c.getValue();
					}
				}
			}
		}
		return "unknown";
	}
}
