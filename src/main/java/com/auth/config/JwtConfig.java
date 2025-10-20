package com.auth.config;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

/**
 * Configuración centralizada para JWT
 * Maneja claves secretas, expiración y configuración de tokens
 */
@Configuration
public class JwtConfig {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration}")
    private Long jwtExpiration;

    @Value("${app.jwt.refresh-expiration}")
    private Long jwtRefreshExpiration;

    @Value("${app.jwt.issuer}")
    private String jwtIssuer;

    /**
     * Obtiene la clave secreta para firmar JWT
     * La clave se decodifica desde Base64
     */
     public SecretKey getSigningKey(){
         byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
         return Keys.hmacShaKeyFor(keyBytes);
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
