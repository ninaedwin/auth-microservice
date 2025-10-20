package com.auth.controller;

import com.auth.config.JwtConfig;
import com.auth.service.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador para operaciones de autenticación
 * Maneja login, refresh token y validación de tokens
 */

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final JwtConfig jwtConfig;


    /**
     * Constructor con todos los parámetros necesarios
     */
    public AuthController(AuthenticationManager authenticationManager,
                          UserDetailsService userDetailsService,
                          JwtService jwtService,
                          JwtConfig jwtConfig){
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtService = jwtService;
        this.jwtConfig = jwtConfig;
    }
}
