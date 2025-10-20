package com.auth.config;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Configuración centralizada para JWT
 * Versión híbrida: Mantiene app.jwt.secret pero usa RSA para firma
 * Maneja claves secretas, expiración y configuración de tokens
 */
@Configuration
public class JwtConfig {

    @Value("${app.jwt.secret:defaultSecretKeyForDevelopmentOnlyChangeInProduction}")
    private String jwtSecret;

    @Value("${app.jwt.expiration}")
    private Long jwtExpiration;

    @Value("${app.jwt.refresh-expiration}")
    private Long jwtRefreshExpiration;

    @Value("${app.jwt.issuer}")
    private String jwtIssuer;

    private final KeyPair rsaKeyPair;

    public JwtConfig() {
        this.rsaKeyPair = generateRsaKey();
    }

    /**
     * Genera par de claves RSA para JWT
     */
    private KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Error generating RSA key pair", ex);
        }
    }

    /**
     * Obtiene la clave pública RSA para verificación
     */
    public PublicKey getPublicKey() {
        return rsaKeyPair.getPublic();
    }

    /**
     * Obtiene la clave privada RSA para firma
     */
    public PrivateKey getPrivateKey() {
        return rsaKeyPair.getPrivate();
    }

    /**
     * Obtiene la clave secreta para firmar JWT HS256 (se mantiene por compatibilidad)
     * La clave se decodifica desde Base64
     */
    public SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Obtiene el secreto en formato String (para otros usos)
     *
     * @return
     */
    public String getJwtSecret() {
        return jwtSecret;
    }

    public Long getExpiration() {
        return jwtExpiration;
    }

    public Long getRefreshExpiration() {
        return jwtRefreshExpiration;
    }

    public String getIssuer() {
        return jwtIssuer;
    }
}
