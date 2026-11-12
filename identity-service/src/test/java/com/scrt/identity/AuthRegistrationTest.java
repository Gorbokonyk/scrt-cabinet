package com.scrt.identity;

import com.scrt.identity.repository.AppUserRepository;
import com.scrt.identity.security.IdentityUserDetailsService;
import jakarta.persistence.EntityManagerFactory;
import org.hibernate.SessionFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.TimeZone;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
class AuthRegistrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:17");

    @Autowired
    IdentityUserDetailsService userDetailsService;

    @Autowired
    EntityManagerFactory emf;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        TimeZone.setDefault(TimeZone.getTimeZone("Europe/Kyiv"));
        registry.add("spring.docker.compose.enabled", () -> false);
    }

    @Autowired
    MockMvc mvc;
    @Autowired
    AppUserRepository users;

    private static final String BODY = """
            {"email":"Test@Example.com","password":"password123","displayName":"Test"}
            """;

    @Test
    void registersUserAndHashesPassword() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated());

        var user = users.findByEmailIgnoreCase("test@example.com").orElseThrow();
        assertThat(user.getPasswordHash()).startsWith("{bcrypt}");
        assertThat(user.getPasswordHash()).doesNotContain("password123");
    }

    @Test
    void duplicateEmailReturnsConflict() throws Exception {
        String body = BODY.replace("Test@Example.com", "dup@example.com");
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isConflict());
    }

    @Test
    void invalidInputReturnsBadRequest() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"not-an-email\",\"password\":\"123\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loadsRegisteredUserForLogin() throws Exception {
        String body = BODY.replace("Test@Example.com", "login@example.com");
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated());

        var details = userDetailsService.loadUserByUsername("login@example.com");
        assertThat(details.isEnabled()).isTrue();
        assertThat(details.isAccountNonLocked()).isTrue();
    }

    @Test
    void loadUserDoesNotTriggerNPlusOne() {
        var stats = emf.unwrap(SessionFactory.class).getStatistics();
        stats.clear();

        userDetailsService.loadUserByUsername("login@example.com");

        // очікуємо рівно 1 prepared statement (join-fetch)
        assertThat(stats.getPrepareStatementCount()).isEqualTo(1);
    }
}