package com.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;
import java.util.UUID;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Configuración principal de seguridad para OAuth2 Authorization Server
 * y protección de endpoints con JWT
 */

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    // Se ha ELIMINADO los métodos
    // ELIMINAR los métodos:
    // - jwkSource()
    // - generateRsaKey()
    // - jwtDecoder()
    // Spring usará el @Bean jwkSource de Jwtconfig

    // =========================================================================
    // OAUTH2 AUTHORIZATION SERVER CONFIGURATION
    // =========================================================================

    /**
     * Configuración del Authorization Server OAuth2
     * Versión actualizada sin métodos deprecados
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // ✅ FORMA CORRECTA en Spring Security 6.x
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Habilita OIDC (OpenID Connect)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()); // Habilita OpenID Connect 1.0

        // Configura el resource server para usar JWT
        http.oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(Customizer.withDefaults())
        );

        return http.build();
    }

    // =========================================================================
    // APPLICATION SECURITY CONFIGURATION
    // =========================================================================

    /**
     * Configuración de seguridad para la aplicación principal
     * Define reglas de acceso a endpoints y configuración JWT
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        // Endpoints públicos
                        .requestMatchers(
                                "/auth/login",
                                "/auth/refresh",
                                "/auth/validate",
                                "/api/public",
                                "/actuator/health",
                                "/h2-console/**"
                        ).permitAll()
                        // Todos los demás endpoints requieren autenticación
                        .anyRequest().authenticated()
                )
                // Configura el resource server para validar JWT
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter()) // CONVERTIR AUTHORITIES
                        )
                )
                // Deshabilitar CSRF para endpoints de auth y H2 console
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(
                                "/auth/**",
                                "/h2-console/**",
                                "/api/public"
                        )
                )
                // Configuración para H2 Console (solo desarrollo)
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.sameOrigin())
                );

        return http.build();
    }

    /**
     * Converter personalizado para extraer authorities del JWT
     */
    private Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            // Extraer authorities del claim "authorities" en el JWT
            @SuppressWarnings("unchecked")
            List<String> authorities = jwt.getClaim("authorities");

            if (authorities == null) {
                System.out.println("No authorities found in JWT token");
                return Collections.emptyList();
            }

            System.out.println("Extracted authorities from JWT: " + authorities);
            return authorities.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        });
        return converter;
    }

    // =========================================================================
    // AUTHENTICATION MANAGER CONFIGURATION
    // =========================================================================

    /**
     * AuthenticationManager personalizado para la autenticación
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder
                .userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder());
        return authenticationManagerBuilder.build();
    }


    // =========================================================================
    // USER MANAGEMENT CONFIGURATION
    // =========================================================================

    /**
     * Servicio de usuarios en memoria
     * En producción usaríamos una base de datos
     * Define usuarios con sus credenciales y roles
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // Usuario regular con rol USER
        UserDetails user = User.builder()
                .username("user@example.com")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();
        // Usuario administrador con roles USER y ADMIN
        UserDetails admin = User.builder()
                .username("admin@example.com")
                .password(passwordEncoder().encode("admin123"))
                .roles("USER", "ADMIN")
                .build();
        // Usuario de solo lectura con rol VIEWER
        UserDetails viewer = User.builder()
                .username("viewer@example.com")
                .password(passwordEncoder().encode("viewer123"))
                .roles("VIEWER")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    /**
     * Codificador de contraseñas BCrypt
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // =========================================================================
    // OAUTH2 CLIENT REGISTRATION
    // =========================================================================

    /**
     * Repositorio de clientes OAuth2 registrados
     * Define qué aplicaciones pueden usar el servidor de autorización
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Cliente para aplicaciones web
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("web-client")
                .clientSecret(passwordEncoder().encode("web-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/login/oauth2/code/web-client")
                .redirectUri("http://127.0.0.1:3000/login/oauth2/code/web-client")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .scope("write")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .build())
                .build();
        // Cliente para aplicaciones móviles
        RegisteredClient mobileClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("mobile-client")
                .clientSecret(passwordEncoder().encode("mobile-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("com.authapp://oauth2/callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(2))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(client);
    }

    // =========================================================================
    // JWT CONFIGURATION
    // =========================================================================

    /**
     * Configuración del Authorization Server
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}