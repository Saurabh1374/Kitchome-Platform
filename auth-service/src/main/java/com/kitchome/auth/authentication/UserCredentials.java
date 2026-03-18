package com.kitchome.auth.authentication;

import java.util.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kitchome.common.exception.ValidationException;
import com.kitchome.auth.payload.RegisterUserDTO;
import com.kitchome.common.exception.ValidationError;
import com.kitchome.auth.payload.ValidationResult;
import com.kitchome.auth.payload.projection.UserCredProjection;
import com.kitchome.auth.util.ErrorCode;
import com.kitchome.auth.util.Role;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.dao.VerificationTokenRepository;
import com.kitchome.auth.entity.VerificationToken;
import com.kitchome.auth.entity.User;

@Service
public class UserCredentials implements UserDetailsService {

	private final UserRepositoryDao userRepo;
	private final PasswordEncoder encryptionStrategy;
	private final ObjectMapper mapper;
	private final com.kitchome.auth.service.EmailService emailService;
	private final VerificationTokenRepository tokenRepository;

	public UserCredentials(UserRepositoryDao userRepo, PasswordEncoder encryptionStrategy, ObjectMapper mapper,
			com.kitchome.auth.service.EmailService emailService,
			VerificationTokenRepository tokenRepository) {
		super();
		this.userRepo = userRepo;
		this.encryptionStrategy = encryptionStrategy;
		this.mapper = mapper;
		this.emailService = emailService;
		this.tokenRepository = tokenRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<UserCredProjection> userOpt = userRepo.findByEmailIgnoreCase(username);
		if (userOpt.isEmpty()) {
			userOpt = userRepo.findByUsernameIgnoreCase(username);
		}

		if (userOpt.isPresent()) {
			return new CustomUserDetails(userOpt.get());
		}

		throw new UsernameNotFoundException("User not found with email or username: " + username);
	}

	public Boolean registerUser(RegisterUserDTO userdto) {
		// 1. Check if user already exists
		Optional<UserCredProjection> existingUserOpt = userRepo.findByEmailIgnoreCase(userdto.getEmail());

		if (existingUserOpt.isPresent()) {
			UserCredProjection existingUser = existingUserOpt.get();
			if (existingUser.isEmailVerified()) {
				// If verified, block registration
				ValidationResult result = new ValidationResult(ValidationError.builder()
						.fieldName("Email")
						.message("Email already exists: " + userdto.getEmail())
						.errorCode(ErrorCode.USER_ALREADY_AVAILABLE.getErrorCode())
						.build());
				throw new ValidationException("Email Already exist", "VALIDATION_ERROR", result.getValidationError());
			} else {
				// If NOT verified, delete old entry and proceed
				User u = userRepo.findById(existingUser.getId()).get();
				// Delete tokens first (due to FK)
				tokenRepository.findByUser(u).ifPresent(tokenRepository::delete);
				userRepo.delete(u);
			}
		}

		// 2. Create new user
		User user = new User();
		user.setUsername(userdto.getUsername());
		user.setEmail(userdto.getEmail());
		user.setPassword(encryptionStrategy.encode(userdto.getPassword()));
		user.setRoles(Collections.singleton(Role.USER));
		user.setEnabled(true);
		user.setEmailVerified(false);

		user = userRepo.save(user);

		// 3. Generate verification token
		String token = UUID.randomUUID().toString();
		VerificationToken myToken = new VerificationToken(user, token);
		tokenRepository.save(myToken);

		// 4. Send verification email async
		emailService.sendVerificationEmail(user.getEmail(), token);

		return true;
	}

	public void verifyUser(String token) {
		VerificationToken vToken = tokenRepository.findByToken(token)
				.orElseThrow(() -> new com.kitchome.auth.Exception.AuthException(ErrorCode.TOKEN_NOT_FOUND,
						"Invalid verification token"));

		if (vToken.getExpiryDate().isBefore(java.time.LocalDateTime.now())) {
			throw new com.kitchome.auth.Exception.AuthException(ErrorCode.TOKEN_EXPIRED, "Verification token expired");
		}

		User user = vToken.getUser();
		user.setEnabled(true);
		user.setEmailVerified(true);
		userRepo.save(user);
		tokenRepository.delete(vToken);
	}

	public void resendVerificationLink(String email) {
		User user = userRepo.findByEmailIgnoreCase(email)
				.map(proj -> {
					User u = new User();
					u.setId(proj.getId());
					u.setEmail(proj.getEmail());
					u.setEnabled(proj.isEnabled());
					// This is a bit awkward with projections, maybe fetch real user
					return userRepo.findById(proj.getId()).get();
				})
				.orElseThrow(() -> new com.kitchome.auth.Exception.AuthException(ErrorCode.VALIDATION_ERROR,
						"User not found"));

		if (user.isEnabled() && user.isEmailVerified()) {
			throw new com.kitchome.auth.Exception.AuthException(ErrorCode.VALIDATION_ERROR,
					"Account is already verified");
		}

		// Delete old token if exists
		tokenRepository.findByUser(user).ifPresent(tokenRepository::delete);

		String newToken = UUID.randomUUID().toString();
		VerificationToken myToken = new VerificationToken(user, newToken);
		tokenRepository.save(myToken);

		emailService.sendVerificationEmail(user.getEmail(), newToken);
	}

	public void updatePassword(User user, String newPassword) {
		user.setPassword(encryptionStrategy.encode(newPassword));
		user.setPasswordLastUpdated(java.time.LocalDateTime.now());
		userRepo.save(user);
	}

	private ValidationResult userAlreadyExists(String email) {
		if (userRepo.existsByEmail(email)) {
			return new ValidationResult(ValidationError.builder()
					.fieldName("Email")
					.message("Email already exists: " + email)
					.errorCode(ErrorCode.USER_ALREADY_AVAILABLE.getErrorCode())
					.build());
		}
		return new ValidationResult();
	}

}
