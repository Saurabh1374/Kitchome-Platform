package com.kitchome.auth.service;

import com.kitchome.auth.authentication.CustomUserDetails;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.entity.User;
import com.kitchome.auth.util.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.RestOperations;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomOAuth2UserServiceTest {

    @Mock
    private UserRepositoryDao userRepository;

    @Mock
    private RestOperations restOperations;

    private CustomOAuth2UserService service;

    @Mock
    private com.kitchome.auth.authentication.UserCredentials userCredentials;

    @BeforeEach
    void setUp() {
        service = new CustomOAuth2UserService(userRepository, userCredentials);
        service.setRestOperations(restOperations);
    }

    private OAuth2UserRequest createRequest() {
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("google")
                .clientId("clientId")
                .clientSecret("clientSecret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/login/oauth2/code/google")
                .authorizationUri("http://auth")
                .tokenUri("http://token")
                .userInfoUri("http://userinfo")
                .userNameAttributeName("email")
                .build();

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "token", Instant.now(), Instant.now().plusSeconds(3600));

        return new OAuth2UserRequest(clientRegistration, accessToken);
    }

    @Test
    void testLoadUser_ExistingUser_NoProviderInitially() {
        OAuth2UserRequest request = createRequest();

        // Mock RestOperations response
        Map<String, Object> attributes = Map.of(
                "email", "test@example.com",
                "name", "Test User",
                "email_verified", true
        );
        ResponseEntity<Map<String, Object>> response = new ResponseEntity<>(attributes, HttpStatus.OK);
        when(restOperations.exchange(any(RequestEntity.class), any(ParameterizedTypeReference.class)))
                .thenReturn(response);

        // Mock DB
        User existingUser = new User();
        existingUser.setId(1L);
        existingUser.setEmail("test@example.com");
        existingUser.setRoles(Set.of(Role.USER));

        when(userRepository.findUserByEmailIgnoreCase("test@example.com")).thenReturn(Optional.of(existingUser));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);

        OAuth2User user = service.loadUser(request);

        assertNotNull(user);
        assertTrue(user instanceof CustomUserDetails);
        CustomUserDetails details = (CustomUserDetails) user;

        assertEquals("test@example.com", details.getEmail());
        assertEquals("google", existingUser.getProvider());
        assertEquals("test@example.com", existingUser.getProviderId()); // the provider ID is the username attribute value

        verify(userRepository).save(any(User.class));
    }

    @Test
    void testLoadUser_ExistingUser_WithProviderAlready() {
        OAuth2UserRequest request = createRequest();

        Map<String, Object> attributes = Map.of(
                "email", "test@example.com",
                "name", "Test User",
                "email_verified", true
        );
        ResponseEntity<Map<String, Object>> response = new ResponseEntity<>(attributes, HttpStatus.OK);
        when(restOperations.exchange(any(RequestEntity.class), any(ParameterizedTypeReference.class)))
                .thenReturn(response);

        User existingUser = new User();
        existingUser.setId(1L);
        existingUser.setEmail("test@example.com");
        existingUser.setProvider("google");
        existingUser.setProviderId("test@example.com");
        existingUser.setRoles(Set.of(Role.ADMIN)); // test picking up existing roles

        when(userRepository.findUserByEmailIgnoreCase("test@example.com")).thenReturn(Optional.of(existingUser));

        OAuth2User user = service.loadUser(request);

        assertTrue(user instanceof CustomUserDetails);
        CustomUserDetails details = (CustomUserDetails) user;

        assertTrue(details.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
        
        // save should NOT be called since provider was already populated
        verify(userRepository, never()).save(any());
    }

    @Test
    void testLoadUser_NewUser() {
        OAuth2UserRequest request = createRequest();

        Map<String, Object> attributes = Map.of(
                "email", "new@example.com",
                "name", "New User",
                "email_verified", true
        );
        ResponseEntity<Map<String, Object>> response = new ResponseEntity<>(attributes, HttpStatus.OK);
        when(restOperations.exchange(any(RequestEntity.class), any(ParameterizedTypeReference.class)))
                .thenReturn(response);

        when(userRepository.findUserByEmailIgnoreCase("new@example.com")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(i -> {
            User u = i.getArgument(0);
            u.setId(2L);
            return u;
        });

        OAuth2User user = service.loadUser(request);

        assertTrue(user instanceof CustomUserDetails);
        CustomUserDetails details = (CustomUserDetails) user;

        assertEquals("new@example.com", details.getEmail());
        assertTrue(details.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));

        verify(userRepository).save(any(User.class));
    }

    @Test
    void testLoadUser_UnverifiedEmail_TriggersNativeVerification() {
        OAuth2UserRequest request = createRequest();

        Map<String, Object> attributes = Map.of(
                "email", "unverified@example.com",
                "name", "Unverified User",
                "email_verified", false
        );
        ResponseEntity<Map<String, Object>> response = new ResponseEntity<>(attributes, HttpStatus.OK);
        when(restOperations.exchange(any(RequestEntity.class), any(ParameterizedTypeReference.class)))
                .thenReturn(response);

        when(userRepository.findUserByEmailIgnoreCase("unverified@example.com")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(i -> {
            User u = i.getArgument(0);
            u.setId(3L);
            return u;
        });

        doNothing().when(userCredentials).resendVerificationLink("unverified@example.com");

        OAuth2User user = service.loadUser(request);

        assertTrue(user instanceof CustomUserDetails);
        CustomUserDetails details = (CustomUserDetails) user;

        assertFalse(details.isEnabled());
        assertFalse(details.isEmailVerified());

        verify(userRepository).save(any(User.class));
        verify(userCredentials).resendVerificationLink("unverified@example.com");
    }
}
