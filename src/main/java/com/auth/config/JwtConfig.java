package com.auth.config;

 import com.nimbusds.jose.jwk.JWKSet;
 import com.nimbusds.jose.jwk.RSAKey;
 import com.nimbusds.jose.jwk.RSAKey;
 import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
 import com.nimbusds.jose.jwk.source.JWKSource;
 import com.nimbusds.jose.proc.SecurityContext;
 import org.springframework.beans.factory.annotation.Value;
 import org.springframework.context.annotation.Bean;
 import org.springframework.context.annotation.Configuration;

 import java.security.KeyPair;
 import java.security.KeyPairGenerator;
 import java.security.interfaces.RSAPrivateKey;
 import java.security.interfaces.RSAPublicKey;
 import java.util.UUID;

/**
 * Configuración centralizada para JWT - ÚNICA fuente de claves RSA
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
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            System.out.println("RSA Key Par generated successfully");
            return keyPair;
        } catch (Exception ex) {
            throw new IllegalStateException("Error generating RSA key pair", ex);
        }
    }

    /**
     * Obtiene la clave pública RSA para verificación
     */
    public RSAPublicKey getPublicKey() {
        return (RSAPublicKey) rsaKeyPair.getPublic();
    }

    /**
     * Obtiene la clave privada RSA para firma
     */
    public RSAPrivateKey getPrivateKey() {
        return (RSAPrivateKey) rsaKeyPair.getPrivate();
    }

    /**
     * Fuente JWK para Spring OAuth2 - USA LAS MISMAS CLAVES
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(){
        RSAKey rsaKey = new RSAKey.Builder(getPublicKey())
                .privateKey(getPrivateKey())
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        System.out.println("JWK Source configured with RSA keys");
        return new ImmutableJWKSet<>(jwkSet);
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

    /**
     * Para debug: mostrar información de las claves
     */
    public void printKeyInfo() {
        RSAPublicKey publicKey = getPublicKey();
        System.out.println("🔑 RSA Public Key Algorithm: " + publicKey.getAlgorithm());
        System.out.println("🔑 RSA Public Key Format: " + publicKey.getFormat());
        System.out.println("🔑 RSA Public Key Modulus: " + publicKey.getModulus().toString(16).substring(0, 32) + "...");
    }
}
