package com.kitchome.auth.controller;

import com.kitchome.auth.authentication.CustomUserDetails;
import com.kitchome.auth.service.AuthenticationService;
import com.kitchome.auth.util.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
class AuthViewControllerTest {

    private MockMvc mockMvc;

    @Mock
    private AuthenticationService authenticationService;

    @InjectMocks
    private AuthViewController authViewController;

    @BeforeEach
    void setUp() {
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/jsp/");
        viewResolver.setSuffix(".jsp");

        mockMvc = MockMvcBuilders.standaloneSetup(authViewController)
                .setViewResolvers(viewResolver)
                .build();
        SecurityContextHolder.clearContext();
    }

    @Test
    void testShowRegistrationForm() throws Exception {
        mockMvc.perform(get("/register"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"));
    }

    @Test
    void testLoginPage() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    void testDashboard() throws Exception {
        mockMvc.perform(get("/dashboard"))
                .andExpect(status().isOk())
                .andExpect(view().name("dashboard"));
    }

    @Test
    void testShowForgotPasswordForm() throws Exception {
        mockMvc.perform(get("/forgot-password"))
                .andExpect(status().isOk())
                .andExpect(view().name("forgot-password"));
    }

    @Test
    void testShowResetPasswordForm() throws Exception {
        mockMvc.perform(get("/reset-password"))
                .andExpect(status().isOk())
                .andExpect(view().name("reset-password"));
    }

    @Test
    void testShowIntegrationsPage() throws Exception {
        mockMvc.perform(get("/integrations"))
                .andExpect(status().isOk())
                .andExpect(view().name("integrations"));
    }

    @Test
    void testShowVerifyEmailPage_Unauthenticated() throws Exception {
        mockMvc.perform(get("/verify-email"))
                .andExpect(status().isOk())
                .andExpect(view().name("verify-email"));
    }

    @Test
    void testShowVerifyEmailPage_AnonymousUser() throws Exception {
        Authentication auth = new AnonymousAuthenticationToken("key", "anonymousUser", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);

        mockMvc.perform(get("/verify-email"))
                .andExpect(status().isOk())
                .andExpect(view().name("verify-email"));
    }

    @Test
    void testShowVerifyEmailPage_Authenticated_Verified() throws Exception {
        CustomUserDetails userDetails = new CustomUserDetails(
                1L, "testuser", "test@example.com",
                Set.of(new SimpleGrantedAuthority("ROLE_USER")),
                Map.of()
        );
        // emailVerified is true by default in this constructor
        ReflectionTestUtils.setField(userDetails, "emailVerified", true);

        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(auth.getPrincipal()).thenReturn(userDetails);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);

        mockMvc.perform(get("/verify-email"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"));
    }

    @Test
    void testShowVerifyEmailPage_Authenticated_Unverified() throws Exception {
        CustomUserDetails userDetails = new CustomUserDetails(
                1L, "testuser", "test@example.com",
                Set.of(new SimpleGrantedAuthority("ROLE_USER")),
                Map.of()
        );
        ReflectionTestUtils.setField(userDetails, "emailVerified", false);

        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(auth.getPrincipal()).thenReturn(userDetails);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);

        mockMvc.perform(get("/verify-email"))
                .andExpect(status().isOk())
                .andExpect(view().name("verify-email"))
                .andExpect(model().attribute("email", "test@example.com"));
    }

    @Test
    void testLogout() throws Exception {
        doNothing().when(authenticationService).logout(any(), any());

        mockMvc.perform(post("/api/v1/auth/logout"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout"));

        verify(authenticationService).logout(any(), any());
    }
}
