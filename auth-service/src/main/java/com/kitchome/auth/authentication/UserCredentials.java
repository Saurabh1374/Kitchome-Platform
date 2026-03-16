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
import com.kitchome.auth.entity.User;

@Service
public class UserCredentials implements UserDetailsService {

	private final UserRepositoryDao userRepo;
	private final PasswordEncoder encryptionStrategy;
	private final ObjectMapper mapper;

	private final com.kitchome.auth.dao.VerificationTokenRepository verificationTokenRepository;
	private final com.kitchome.auth.service.EmailService emailService;

	public UserCredentials(UserRepositoryDao userRepo, PasswordEncoder encryptionStrategy, ObjectMapper mapper,
			com.kitchome.auth.dao.VerificationTokenRepository verificationTokenRepository,
			com.kitchome.auth.service.EmailService emailService) {
		super();
		this.userRepo = userRepo;
		this.encryptionStrategy = encryptionStrategy;
		this.mapper = mapper;
		this.verificationTokenRepository = verificationTokenRepository;
		this.emailService = emailService;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		Optional<UserCredProjection> userOpt = userRepo.findByEmailIgnoreCase(username);
		if (userOpt.isEmpty()) {
			userOpt = userRepo.findByUsernameIgnoreCase(username);
		}

		return userOpt.map(CustomUserDetails::new)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with email or username: " + username));

	}

	public Boolean registerUser(RegisterUserDTO userdto) {
		// register user
		ValidationResult result = userAlreadyExists(userdto.getEmail());
		if (!result.isvalid()) {
			throw new ValidationException("Email Already exist", "VALIDATION_ERROR", result.getValidationError());
		}
		userdto.setPassword(encryptionStrategy.encode(userdto.getPassword()));
		User user = mapper.convertValue(userdto, User.class);
		user.setRoles(Role.USER);
		user.setEnabled(false); // Disable until verified
		userRepo.save(user);

		// Generate Verification Token
		String token = UUID.randomUUID().toString();
		com.kitchome.auth.entity.VerificationToken verificationToken = new com.kitchome.auth.entity.VerificationToken(
				user, token);
		verificationTokenRepository.save(verificationToken);

		// Send real email
		emailService.sendVerificationEmail(user.getEmail(), token);

		return true;
	}

	public void verifyEmail(String token) {
		com.kitchome.auth.entity.VerificationToken verificationToken = verificationTokenRepository.findByToken(token)
				.orElseThrow(() -> new com.kitchome.auth.Exception.AuthException(ErrorCode.TOKEN_NOT_FOUND,
						"Invalid verification token"));

		if (verificationToken.getExpiryDate().isBefore(java.time.LocalDateTime.now())) {
			throw new com.kitchome.auth.Exception.AuthException(ErrorCode.TOKEN_EXPIRED, "Verification token expired");
		}

		User user = verificationToken.getUser();
		user.setEnabled(true);
		userRepo.save(user);

		verificationTokenRepository.delete(verificationToken);
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
