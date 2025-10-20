package com.auth.controller;

import com.auth.config.JwtConfig;
import com.auth.dto.AuthRequest;
import com.auth.dto.AuthResponse;
import com.auth.service.JwtService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

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

    // =========================================================================
    // AUTHENTICATION ENDPOINTS
    // =========================================================================

    /**
     * Endpoint para login de usuarios
     * Valida credenciales y retorna JWT tokens
     *
     * Ejemplo de request:
     * POST /auth/login
     * {
     *   "email": "user@example.com",
     *   "password": "password"
     * }
     *
     * Ejemplo de response:
     * {
     *   "access_token": "eyJhbGciOiJIUzI1NiIs...",
     *   "token_type": "Bearer",
     *   "expires_in": 86400,
     *   "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
     *   "scope": "read write profile"
     * }
     */

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest request){
        try {
            // Atenticar usuario
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );

            // Cargar detalles del usuario
            final UserDetails userDetails = userDetailsService.loadUserByUsername(request.email());

            // Generar tokens
            final String accessToken = jwtService.generateToken(userDetails);
            final String refreshToken = jwtService.generateRefreshToken(userDetails);

            // Crear response
            AuthResponse response = new AuthResponse(
                    accessToken,
                    "Bearer",
                    jwtConfig.getExpiration()/1000 // Convertir a segundos
                    refreshToken,
                    "read write profile"
            );

            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "error", "Invalid credentials",
                            "messange", "Email or passwrod is incorrect"
                    ));
        } catch (Exception e){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "error", "Authentication failed",
                            "messange", e.getMessage()
                            ));
        }
    }


}
