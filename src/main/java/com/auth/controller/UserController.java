package com.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Controlador para endpoints protegidos que demuestran el uso de JWT
 * Incluy ejemplos de proyección por roles y autenticación
 */

@RestController
@RequestMapping("/api")
public class UserController {
    // =========================================================================
    // PUBLIC ENDPOINTS - NO REQUIEREN AUTENTICACIÓN
    // =========================================================================

    /**
     * Endpoint público - accesible sin token
     * <p>
     * Ejemplo de request:
     * GET /api/public
     * <p>
     * Ejemplo de response:
     * {
     * "message": "✅ Este es un endpoint público - Acceso libre para todos",
     * "timestamp": "2024-01-15T10:30:00.123456",
     * "authentication_required": false
     * }
     */
    @GetMapping("/public")
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Este es un endpoint público - Acceso libre para todos");
        response.put("timestamp", LocalDateTime.now());
        response.put("authentication_required", false);

        return ResponseEntity.ok(response);
    }

    // =========================================================================
    // PROTECTED ENDPOINTS - REQUIEREN AUTENTICACIÓN
    // =========================================================================

    /**
     * Endpoint protegido - requiere token JWT válido
     * <p>
     * Ejemplo de request:
     * GET /api/protected
     * Header: Authorization: Bearer {access_token}
     * <p>
     * Ejemplo de response:
     * {
     * "message": "🔒 Acceso a endpoint protegido - Token VÁLIDO ✅",
     * "username": "user@example.com",
     * "authorities": ["ROLE_USER"],
     * "timestamp": "2024-01-15T10:31:00.123456",
     * "authentication_required": true
     * }
     */

    @GetMapping("/protected")
    public ResponseEntity<Map<String, Object>> protectedEndpoint() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Acceso a endpoint protegido - TOKEN VALIDO");
        response.put("username", username);
        response.put("authorities", authorities); // ahora es una lista
        response.put("timestamp", LocalDateTime.now());
        response.put("authentication_required", true);
        System.out.println("User " + username + " has authorities: " + authorities);
        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint de perfil de usuario - requiere autenticación
     * <p>
     * Ejemplo de request:
     * GET /api/profile
     * Header: Authorization: Bearer {access_token}
     * <p>
     * Ejemplo de response:
     * {
     * "username": "user@example.com",
     * "email": "user@example.com",
     * "full_name": "Usuario Demo",
     * "profile_type": "STANDARD",
     * "member_since": "2024-01-01",
     * "last_login": "2024-01-15T10:31:00.123456"
     * }
     */

    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        //OBTENER ROL PRINCIPAL
        String mainRole = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst()
                .orElse("USER");

        Map<String, Object> response = new HashMap<>();
        response.put("username", username);
        response.put("email", username);
        response.put("full_name", "Usuario Demo");
        response.put("profile_type", mainRole.replace("ROLE_",""));
        response.put("roles", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        response.put("member_since", "2024-01-01");
        response.put("last_login", LocalDateTime.now());

        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint para obtener información del usuario actual
     *
     * Ejemplo de request:
     * GET /api/me
     * Header: Authorization: Bearer {access_token}
     *
     * Ejemplo de response:
     * {
     *   "user": {
     *     "username": "user@example.com",
     *     "authenticated": true,
     *     "authorities": ["ROLE_USER"]
     *   },
     *   "authentication": {
     *     "type": "UsernamePasswordAuthenticationToken",
     *     "principal": "User"
     *   }
     * }
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String username = authentication.getName();
        List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("user", Map.of(
                "username", username,
                "authenticated", authentication.isAuthenticated(),
                "authorities", authorities
        ));
        response.put("authentication", Map.of(
                "type", authentication.getClass().getSimpleName(),
                "principal", authentication.getPrincipal().getClass().getSimpleName()
        ));

        return ResponseEntity.ok(response);
    }
}
