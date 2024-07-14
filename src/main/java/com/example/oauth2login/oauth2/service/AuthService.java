package com.example.oauth2login.oauth2.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class AuthService {

    public String getUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        log.info("Name={}", authentication.getName());
        return authentication.getName();

    }
}
