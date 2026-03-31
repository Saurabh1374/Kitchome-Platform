package com.kitchome.auth.service;

import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.util.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.kitchome.auth.authentication.CustomUserDetails;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Lazy;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepositoryDao userRepository;
    
    @Lazy
    private final com.kitchome.auth.authentication.UserCredentials userCredentials;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId();
        String providerId = oAuth2User.getName();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        log.info("Processing OAuth2 login for provider: {}, email: {}", provider, email);

        // Explicitly check for verification claim (Google returns Boolean)
        Boolean isOauthEmailVerified = oAuth2User.getAttribute("email_verified");
        boolean emailVerified = (isOauthEmailVerified != null && isOauthEmailVerified);

        Optional<User> userOptional = userRepository.findUserByEmailIgnoreCase(email);
        User user;
        boolean triggerVerificationEmail = false;

        if (userOptional.isPresent()) {
            user = userOptional.get();
            // Update existing user with provider info if not already set
            if (user.getProvider() == null) {
                user.setProvider(provider);
                user.setProviderId(providerId);
                if (emailVerified) {
                    user.setEmailVerified(true);
                    user.setEnabled(true);
                } else if (!user.isEmailVerified()) {
                    // It was an existing user but they were never verified natively either!
                    user.setEnabled(false);
                    triggerVerificationEmail = true;
                }
                user = userRepository.save(user);
            } else if (!user.isEmailVerified() && !emailVerified) {
                user.setEnabled(false);
                triggerVerificationEmail = true;
                user = userRepository.save(user);
            }
        } else {
            // Register new user
            user = new User();
            user.setEmail(email);
            user.setUsername(email); // Use email as username for social login
            user.setProvider(provider);
            user.setProviderId(providerId);
            user.setEnabled(emailVerified);
            user.setEmailVerified(emailVerified);
            user.setRoles(Set.of(Role.USER));
            user = userRepository.save(user);
            
            if (!emailVerified) {
                triggerVerificationEmail = true;
            }
            log.info("Created new user via OAuth2 for email: {}, verified: {}", email, emailVerified);
        }

        // Trigger native email flow if the OAuth provider did not guarantee verification
        if (triggerVerificationEmail) {
            log.warn("OAuth provider did not verify email {}. Triggering native KitChome verification.", email);
            userCredentials.resendVerificationLink(email);
        }

        Set<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role.getRole()))
                .collect(Collectors.toSet());

        if (authorities.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return new CustomUserDetails(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                authorities,
                oAuth2User.getAttributes(),
                user.isEnabled(),
                user.isEmailVerified()
        );
    }
}
