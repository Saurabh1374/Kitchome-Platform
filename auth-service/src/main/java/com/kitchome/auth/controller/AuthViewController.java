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

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.stream.Collectors;

@Controller
public class AuthViewController {

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
    public String showVerifyEmailPage() {
        return "verify-email";
    }
}
