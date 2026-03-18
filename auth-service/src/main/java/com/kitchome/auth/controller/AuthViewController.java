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
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class AuthViewController {

    private final AuthenticationService authService;


    @GetMapping("/register")
    public String showRegistrationForm() {
        return "register"; // Resolves to register.html
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login"; // Resolves to login.html
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
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
