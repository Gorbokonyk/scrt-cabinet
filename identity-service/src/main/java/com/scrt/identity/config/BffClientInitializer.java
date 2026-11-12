package com.scrt.identity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

/**
 * Конфігурація для автоматичної реєстрації OAuth2-клієнта BFF (Backend-for-Frontend)
 * у Spring Authorization Server.

 * Під час старту застосування створює та зберігає клієнта з ідентифікатором
 * scrt-bff, якщо він ще не існує в репозиторії. Реєстрація є ідемпотентною,
 * що дозволяє безпечно використовувати клас із постійними сховищами (наприклад, БД).

 * Налаштування клієнта відповідають сучасним рекомендаціям OAuth 2.1 / OIDC
 * для BFF-архітектури: обов'язковий PKCE, ротація refresh-токенів, короткий TTL
 * access-токена.
 */
@Configuration
public class BffClientInitializer {

    /**
     * Реєструє BFF-клієнта scrt-bff у репозиторії зареєстрованих клієнтів
     * після повного старту контексту Spring.

     * Повертає ApplicationRunner, який Spring Boot виконує один раз
     * під час запуску застосування. Якщо клієнт із таким clientId уже
     * присутній у репозиторії, реєстрація пропускається (ідемпотентність).
     *
     * @param clients     репозиторій зареєстрованих OAuth2-клієнтів (in-memory, JDBC тощо)
     * @param encoder     кодувальник для хешування клієнтського секрету перед збереженням
     * @param secret      клієнтський секрет, інжектиться з властивості scrt.bff.client-secret
     * @param redirectUri дозволений URI перенаправлення після авторизації,
     *                    інжектиться з властивості scrt.bff.redirect-uri
     * @return бін ApplicationRunner, що виконує реєстрацію клієнта під час старту
     */
    @Bean
    ApplicationRunner registerBffClient(
            RegisteredClientRepository clients,
            PasswordEncoder encoder,
            @Value("${scrt.bff.client-secret}") String secret,
            @Value("${scrt.bff.redirect-uri}") String redirectUri) {
        return args -> {
            // Ідемпотентність: якщо клієнт уже зареєстрований — нічого не робимо,
            // щоб уникнути дублювання записів у постійному сховищі.
            if (clients.findByClientId("scrt-bff") != null) {
                return;
            }

            // Створення та збереження нового BFF-клієнта.
            clients.save(RegisteredClient.withId(UUID.randomUUID().toString())
                    // Ідентифікатор клієнта та його людяночитана назва.
                    .clientId("scrt-bff")
                    .clientName("SCRT BFF")
                    // Секрет зберігається лише у вигляді хешу — ніколи у відкритому вигляді.
                    .clientSecret(encoder.encode(secret))
                    // Автентифікація клієнта через HTTP Basic (client_id + client_secret).
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    // Дозволені grant-типи: код авторизації та оновлення токена.
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    // Єдиний дозволений URI перенаправлення після авторизації.
                    .redirectUri(redirectUri)
                    // Стандартні OIDC-скоупи для ідентифікації користувача.
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .clientSettings(ClientSettings.builder()
                            // Обов'язковий PKCE (Proof Key for Code Exchange) — захист
                            // від перехоплення authorization code.
                            .requireProofKey(true)
                            // Екран згоди не показується — клієнт є довіреним first-party.
                            .requireAuthorizationConsent(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            // Короткоживучий access-токен обмежує вікно зловживання
                            // у разі його витоку.
                            .accessTokenTimeToLive(Duration.ofMinutes(10))
                            // Refresh-токен живе довше, дозволяючи оновлювати сесію.
                            .refreshTokenTimeToLive(Duration.ofDays(7))
                            // Ротація refresh-токенів: кожне оновлення видає новий токен,
                            // що знижує ризик компрометації.
                            .reuseRefreshTokens(false)
                            .build())
                    .build());
        };
    }
}