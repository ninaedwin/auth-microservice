package com.auth.service;

import com.auth.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Servicio para operaciones con JWT - CORREGIDO para usar RSA
 * - Generación de tokens
 * - Validación de tokens
 * - Extracción de información de tokens
 */
@Service
public class JwtService {

    private final JwtConfig jwtConfig;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public JwtService(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
        this.privateKey = jwtConfig.getPrivateKey();
        this.publicKey = jwtConfig.getPublicKey();
    }

    // =========================================================================
    // TOKEN GENERATION METHODS - VERSIÓN CORREGIDA
    // =========================================================================

    /**
     * Genera un access token JWT para el usuario usando RSA
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("token_type", "access");
        return buildToken(claims, userDetails, jwtConfig.getExpiration());
    }

    /**
     * Genera un refresh token JWT para el usuario usando RSA
     */
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("token_type", "refresh");
        return buildToken(claims, userDetails, jwtConfig.getRefreshExpiration());
    }

    /**
     * Método interno para generar tokens JWT con RSA- CORREGIDO
     */
    private String buildToken(Map<String, Object> claims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuer(jwtConfig.getIssuer())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(expiration)))
                .signWith(privateKey, Jwts.SIG.RS256) // Firma con RSA
                .compact();
    }

    // =========================================================================
    // TOKEN VALIDATION METHODS
    // =========================================================================

    /**
     * Valida si un token JWT es válido para el usuario
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Valida si un token JWT es válido (sin verificar usuario específico)
     */
    public boolean isTokenValid(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extrae el username del token JWT
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrae el tipo de token (access/refresh)
     */
    public String extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get("token_type", String.class));
    }

    // =========================================================================
    // CLAIM EXTRACTION METHODS
    // =========================================================================

    /**
     * Extrae un claim específico del token JWT
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extrae todos los claims del token JWT
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Verifica si el token JWT ha expirado
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extrae la fecha de expiración del token JWT
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}