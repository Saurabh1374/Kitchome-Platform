package com.kitchome.auth.controller;

import com.kitchome.auth.authentication.CustomUserDetails;
import org.apache.coyote.BadRequestException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import lombok.RequiredArgsConstructor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.kitchome.auth.service.AuthenticationService;
import org.springframework.web.bind.annotation.PostMapping;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

import com.kitchome.auth.service.PromotionService;
import com.kitchome.auth.payload.UnifiedProfileResponseDTO;
import com.kitchome.auth.dao.UserRepositoryDao;
import com.kitchome.auth.dao.OrganizationRepository;
import com.kitchome.auth.entity.User;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequiredArgsConstructor
@Slf4j
public class AuthViewController {

    private final AuthenticationService authService;
    private final PromotionService promotionService;
    private final UserRepositoryDao userRepo;
    private final OrganizationRepository organizationRepo;


    @GetMapping("/register")
    public String showRegistrationForm() {
        return "register"; // Resolves to register.html
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login"; // Resolves to login.html
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        model.addAttribute("isAdmin", false);
        model.addAttribute("pendingOnboardingsCount", 0);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            User currentUser = userRepo.findByUsername(auth.getName())
                    .or(() -> userRepo.findUserByUsernameIgnoreCase(auth.getName()))
                    .or(() -> userRepo.findUserByEmailIgnoreCase(auth.getName()))
                    .orElse(null);
            model.addAttribute("currentUser", currentUser);

            if (currentUser != null) {
                boolean isAdmin = currentUser.getRoles() != null &&
                        currentUser.getRoles().stream().anyMatch(r -> r.name().contains("ADMIN"));
                if (!isAdmin && !currentUser.isEnabled()) {
                    // Pending user: route to onboarding waiting room
                    return "redirect:/onboarding";
                }
                model.addAttribute("isAdmin", isAdmin);
                if (isAdmin) {
                    List<User> pendingUsers = userRepo.findByEnabledFalse();
                    model.addAttribute("pendingOnboardings", pendingUsers);
                    model.addAttribute("pendingOnboardingsCount", pendingUsers.size());
                }
            }

            try {
                UnifiedProfileResponseDTO profile = promotionService.getUnifiedProfile(auth.getName());
                model.addAttribute("profile", profile);
                if (currentUser == null) {
                    boolean isAdmin = profile.getRoles() != null && profile.getRoles().contains("ADMIN");
                    model.addAttribute("isAdmin", isAdmin);
                    if (isAdmin) {
                        List<User> pendingUsers = userRepo.findByEnabledFalse();
                        model.addAttribute("pendingOnboardings", pendingUsers);
                        model.addAttribute("pendingOnboardingsCount", pendingUsers.size());
                    }
                }
            } catch (Exception e) {
                log.warn("Could not pre-load unified profile for {}: {}", auth.getName(), e.getMessage());
            }
        }
        return "dashboard";
    }

    @GetMapping({"/onboarding", "/onboardings", "/admin/onboardings"})
    public String showOnboardingsPage(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken));
        model.addAttribute("isAuthenticated", isAuthenticated);
        model.addAttribute("isAdmin", false);
        model.addAttribute("pendingOnboardingsCount", 0);

        if (isAuthenticated) {
            User currentUser = userRepo.findByUsername(auth.getName())
                    .or(() -> userRepo.findUserByUsernameIgnoreCase(auth.getName()))
                    .or(() -> userRepo.findUserByEmailIgnoreCase(auth.getName()))
                    .orElse(null);
            model.addAttribute("currentUser", currentUser);

            boolean isAdmin = (currentUser != null && currentUser.getRoles() != null &&
                    currentUser.getRoles().stream().anyMatch(r -> r.name().contains("ADMIN")));

            try {
                UnifiedProfileResponseDTO profile = promotionService.getUnifiedProfile(auth.getName());
                model.addAttribute("profile", profile);
                if (profile != null && profile.getRoles() != null && profile.getRoles().contains("ADMIN")) {
                    isAdmin = true;
                }
            } catch (Exception e) {
                log.warn("Error loading unified profile for {}: {}", auth.getName(), e.getMessage());
            }

            model.addAttribute("isAdmin", isAdmin);

            if (isAdmin) {
                try {
                    List<User> pendingUsers = userRepo.findByEnabledFalse();
                    model.addAttribute("pendingUsers", pendingUsers);
                    model.addAttribute("pendingOnboardingsCount", pendingUsers.size());
                    model.addAttribute("organizations", organizationRepo.findAll());
                    model.addAttribute("approvedUsers", userRepo.findByEnabled(true));
                } catch (Exception e) {
                    log.error("Error loading admin onboarding tables: {}", e.getMessage());
                }
            }
        }
        return "onboardings";
    }

    @GetMapping("/forgot-password")
    public String showForgotPasswordForm() {
        return "forgot-password";
    }

    @GetMapping("/reset-password")
    public String showResetPasswordForm() {
        return "reset-password";
    }

    @GetMapping("/verify-email")
    public String showVerifyEmailPage(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            Object principal = auth.getPrincipal();
            if (principal instanceof CustomUserDetails) {
                CustomUserDetails user = (CustomUserDetails) principal;
                model.addAttribute("email", user.getEmail());
                if (user.isEmailVerified()) {
                    return "redirect:/dashboard";
                }
            }
        }
        return "verify-email";
    }

    @GetMapping("/integrations")
    public String showIntegrationsPage() {
        return "integrations";
    }

    @PostMapping("/api/v1/auth/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(request, response);
        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }
        return "redirect:/login?logout";
    }
}
