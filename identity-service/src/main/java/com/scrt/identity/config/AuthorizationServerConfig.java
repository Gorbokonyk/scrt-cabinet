package com.scrt.identity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * Конфігурація безпеки для додатку, що виконує роль OAuth2 Authorization Server
 * та Resource Server.

 * Клас визначає два ланцюжки фільтрів (SecurityFilterChain), які працюють послідовно
 * завдяки анотації Order:

 * 1. Перший ланцюжок (Order 1): Обробляє суто OAuth2/OIDC ендпоінти
 *    (наприклад, /oauth2/authorize, /oauth2/token). Він також налаштовує перевірку
 *    JWT-токенів для захисту ресурсів API.

 * 2. Другий ланцюжок (Order 2): Обробляє всі інші запити. Відповідає за
 *    публічні ендпоінти (реєстрація, healthcheck) та надає сторінку логіну для
 *    отримання сесії користувачем.
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

        http.with(authorizationServerConfigurer, (authorizationServer) ->
                authorizationServer.oidc(Customizer.withDefaults())
        );

        http
                .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
                        .requestMatchers("/login", "/error").permitAll()
                        .anyRequest().denyAll())
                .formLogin(Customizer.withDefaults());
        return http.build();
    }
}
