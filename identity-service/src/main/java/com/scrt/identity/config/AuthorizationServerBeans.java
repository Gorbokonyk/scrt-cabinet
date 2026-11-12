package com.scrt.identity.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.scrt.identity.security.IdentityUserDetails;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/**
 * Конфігурація основних бінів для OAuth2 Authorization Server.
 * Цей клас визначає фундаментальні компоненти, необхідні для роботи протоколу
 * авторизації: реєстрацію клієнтів, зберігання виданих авторизацій, криптографічні
 * ключі для підпису JWT та налаштування їх вмісту.
 */
@Configuration
public class AuthorizationServerBeans {

    /**
     * Налаштовує репозиторій зареєстрованих клієнтів (RegisteredClient).
     */
    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbc) {
        return new JdbcRegisteredClientRepository(jdbc);
    }

    /**
     * Сервіс для управління життєвим циклом авторизацій (кодів, токенів).
     * зберігає дані в базі даних (наприклад, JDBC).
     *
     * @return сервіс авторизації
     */
    @Bean
    OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(jdbc, clients);
    }

    /**
     * Сервіс для управління згодами користувачів (Consent).
     * <p>
     * Відповідає за зберігання того, на які scope (дозволи) користувач
     * дав згоду для конкретного клієнта.
     *
     * @return сервіс згод
     */
    @Bean
    OAuth2AuthorizationConsentService consentService(
            JdbcTemplate jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
    }

    /**
     * Джерело криптографічних ключів (JWKSource) для підпису JWT-токенів.

     * Генерує пару ключів RSA (2048 біт) під час старту додатку. Ці ключі
     * використовуються сервером для підпису access-токенів, а також публікуються
     * на ендпоінті /oauth2/jwks, щоб інші сервіси могли перевірити підпис.
     *
     * @return джерело ключів
     * @throws Exception якщо не вдалося згенерувати ключі
     */
    @Bean
    JWKSource<SecurityContext> jwkSource() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /**
     * Декодер JWT-токенів.

     * Використовується сервером для перевірки валідності токенів, які
     * надходять від клієнтів. Він автоматично бере публічні ключі з {@link JWKSource}.
     *
     * @param jwkSource джерело ключів
     * @return декодер JWT
     */
    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Загальні налаштування сервера авторизації.

     * Визначає "issuer" (видавця токенів) — базову URL-адресу, яка буде
     * вказана в полі "iss" всередині JWT-токенів.
     *
     * @param issuer URL видавця з конфігурації
     * @return налаштування сервера
     */
    @Bean
    AuthorizationServerSettings authorizationServerSettings(
            @Value("${scrt.issuer}") String issuer) {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    /**
     * Кастомізатор вмісту JWT-токенів (Access Token).
     * <p>
     * Дозволяє додати власні claims (поля) до стандартного токена.
     * У цьому випадку в токен додаються:
     * 1. "uid" — унікальний ідентифікатор користувача (UUID).
     * 2. "authorities" — список прав доступу (ролей та дозволів) користувача,
     * які відфільтровані та відсортовані для конкретного клієнта (clientId).
     *
     * @return кастомізатор токенів
     */
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            // Застосовуємо кастомізацію лише для Access Token
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }

            // Перевіряємо, чи є принципал (користувач) нашим IdentityUserDetails
            var principal = context.getPrincipal();
            if (!(principal.getPrincipal() instanceof IdentityUserDetails user)) {
                return;
            }

            // Формуємо префікс для фільтрації прав (наприклад, "scrt-bff:")
            String prefix = context.getRegisteredClient().getClientId() + ":";

            // Беремо лише ті права, що належать поточному клієнту,
            // відрізаємо префікс і сортуємо
            var authorities = user.getAuthorities().stream()
                    .map(a -> a.getAuthority())
                    .filter(a -> a.startsWith(prefix))
                    .map(a -> a.substring(prefix.length()))
                    .sorted()
                    .toList();

            // Додаємо кастомні поля в JWT
            context.getClaims().claim("uid", user.getId().toString());
            context.getClaims().claim("authorities", authorities);
        };
    }


    /**
     * Створює та повертає джерело JWK (JSON Web Key) для підпису й перевірки
     * JWT-токенів, що видаються Spring Authorization Server.
     * <p>
     * Метод реалізує схему "persistent key" — ключ генерується один раз
     * і зберігається у файлі на диску. Це критично важливо для авторизаційного
     * сервера: якщо ключ змінюватиметься під час кожного перезапуску, усі
     * раніше видані токени стануть недійсними, а клієнти не зможуть їх
     * перевірити.
     * <p>
     * Логіка роботи:
     * 1. Якщо файл із ключем існує — ключ читається з нього та парситься
     * у RSAKey. Це забезпечує стабільність ключа між перезапусками.
     * 2. Якщо файлу немає — генерується новий RSA-ключ довжиною 2048 біт
     * з випадковим keyID, створюється директорія (за потреби) і ключ
     * зберігається у файл у форматі JSON.
     * <p>
     * Повертається ImmutableJWKSet — незмінне джерело JWK, що містить
     * один RSA-ключ. ImmutableJWKSet гарантує, що набір ключів не буде
     * випадково змінений під час роботи застосування.
     *
     * @param keyFile шлях до файлу з ключем (JSON). За замовчуванням —
     *                ./.keys/jwk.json. Може бути перевизначений через
     *                властивість scrt.jwt.key-file.
     * @return джерело JWK для підпису та перевірки JWT
     * @throws Exception якщо не вдалося прочитати, згенерувати, створити
     *                   директорію або записати файл ключа
     */
    @Bean
    JWKSource<SecurityContext> jwkSourceScrt(
            @Value("${scrt.jwt.key-file:./.keys/jwk.json}") String keyFile) throws Exception {
        Path path = Path.of(keyFile);
        RSAKey rsaKey;
        if (Files.exists(path)) {
            rsaKey = RSAKey.parse(Files.readString(path));
        } else {
            rsaKey = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
            Files.createDirectories(path.toAbsolutePath().getParent());
            Files.writeString(path, rsaKey.toJSONString());
        }
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }
}