package com.kitchome.auth.events;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {
        log.error("Login failed due to : {}", exception.getMessage());
        if (exception instanceof SessionAuthenticationException &&
                exception.getMessage().contains("Maximum sessions")) {
            response.sendRedirect("/api/v1/users/login?session=maxed");
        } else {
            response.sendRedirect("/api/v1/users/login?error=true");
        }
    }
}
