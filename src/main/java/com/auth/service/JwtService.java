package com.auth.service;

import com.auth.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Servicio para operaciones con JWT - CORREGIDO  USA LAS MISMAS CLAVES RSA - INCLUYE AUTHORITIES
 */
@Service
public class JwtService {

    private final JwtConfig jwtConfig;
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public JwtService(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
        this.privateKey = jwtConfig.getPrivateKey();
        this.publicKey = jwtConfig.getPublicKey();

        // Debug info
        System.out.println("✅ JwtService initialized with RSA keys");
        System.out.println("🔑 Private Key Algorithm: " + privateKey.getAlgorithm());
        System.out.println("🔑 Public Key Algorithm: " + publicKey.getAlgorithm());
    }

    // =========================================================================
    // TOKEN GENERATION METHODS - VERSIÓN CORREGIDA
    // =========================================================================

    /**
     * Genera un access token JWT para el usuario usando RSA incluyendo authorities
     *
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("token_type", "access");
        // INCLUIR AUTHORITIES EN EL TOKEN
        List<String> authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        claims.put("authorities", authorities);
        System.out.println("Including authorities in token: " + authorities);
        String token = buildToken(claims, userDetails, jwtConfig.getExpiration());
        System.out.println("✅ Access Token generated for: " + userDetails.getUsername());
        return token;
    }

    /**
     * Genera un refresh token JWT para el usuario usando RSA
     */
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("token_type", "refresh");
        String token = buildToken(claims, userDetails, jwtConfig.getRefreshExpiration());
        System.out.println("✅ Refresh Token generated for: " + userDetails.getUsername());
        return token;
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
                .signWith(privateKey, Jwts.SIG.RS256) // MISMA CLAVE PRIVADA
                .compact();
    }

    /**
     * Extrae las authorities del token JWT
     */
    @SuppressWarnings("unchecked")
    public List<String> extractAuthorities(String token) {
        return extractClaim(token, claims -> {
            Object authorities = claims.get("authorities");
            if (authorities instanceof List) {
                return (List<String>) authorities;
            }
            return List.of();
        });
    }
    // =========================================================================
    // TOKEN VALIDATION METHODS
    // =========================================================================

    /**
     * Valida si un token JWT es válido para el usuario
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        boolean isValid = (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        System.out.println("🔍 Token validation for " + username + ": " + (isValid ? "VALID" : "INVALID"));
        return isValid;
    }

    /**
     * Valida si un token JWT es válido (sin verificar usuario específico)
     */
    public boolean isTokenValid(String token) {
        try {
            boolean isValid = !isTokenExpired(token);
            System.out.println("🔍 Token validation: " + (isValid ? "VALID" : "EXPIRED"));
            return isValid;
        } catch (Exception e) {
            System.out.println("❌ Token validation error: " + e.getMessage());
            return false;
        }
    }


    // =========================================================================
    // CLAIM EXTRACTION METHODS
    // =========================================================================

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
                .verifyWith(publicKey) // MISMA CLAVE PÚBLICA
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