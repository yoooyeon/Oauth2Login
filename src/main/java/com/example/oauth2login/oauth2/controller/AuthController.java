package com.example.oauth2login.oauth2.controller;

import com.example.oauth2login.oauth2.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/users")
    public String getUserInfo(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        model.addAttribute("name", userDetails.getUsername());
        return "index";

    }
}
