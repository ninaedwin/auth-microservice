package com.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Clase principal de la aplicación Spring Boot
 * Inicia el microservicio de autenticación con OAuth2 y JWT
 */

@SpringBootApplication
public class AuthMicroserviceApplication {

	public static void main(String[] args) {
        SpringApplication.run(AuthMicroserviceApplication.class, args);
	}

}
