package org.d3softtech.oauth2.server;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.HttpHeaders.LOCATION;
import static org.springframework.http.HttpHeaders.SET_COOKIE;

import java.net.URI;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest
public class AuthorizationServerTest {

    private WebTestClient webTestClient;


    @BeforeEach
    public void beforeTest() {
        webTestClient = WebTestClient.bindToServer()
            .baseUrl("http://localhost:6060")
            .build();
    }

    @Test
    void verifyMetaDataEndpoint_OrWellKnownEndPoint() {
        webTestClient.get().uri(uriBuilder -> uriBuilder.path("/.well-known/oauth-authorization-server").build())
            .exchange()
            .expectStatus().isOk()
            .expectBody().json(getExcpectedJson());
    }

    @Test
    void verifyTokenEndpoint() {
        webTestClient.post()
            .uri(uriBuilder -> uriBuilder.path("/oauth2/token").queryParam("grant_type", "client_credentials").build())
            .headers(httpHeaders -> httpHeaders.setBasicAuth("spring-test", "test-secret")).exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.access_token").exists()
            .jsonPath("$.token_type").isEqualTo("Bearer")
            .jsonPath("$.expires_in").isEqualTo(299);
    }

    @Test
    void verifyAuthorizeEndpoint() {

        AtomicReference<String> location = new AtomicReference<>();
        AtomicReference<HttpHeaders> headers = new AtomicReference<>();
        webTestClient.get()
            .uri(uriBuilder -> uriBuilder.path("/oauth2/authorize").queryParam("grant_type", "authorization_code")
                .build())
            .exchange()
            .expectStatus().isFound().expectHeader()
            .value(LOCATION, value -> {
                location.set(value);
                assertTrue(value.startsWith("http://localhost:6060/login"));
            });
        webTestClient.post().uri(uriBuilder -> uriBuilder.path(URI.create(location.get()).getPath()).build())
            .headers(httpHeaders -> httpHeaders.setBasicAuth("user1", "password")).exchange().expectHeader()
            .value(SET_COOKIE,
                header -> {
                    System.out.println("Cookies:::::" + header);
                    assertEquals("", header);
                });

        webTestClient.get()
            .uri(uriBuilder -> uriBuilder.path("/oauth2/authorize").queryParam("grant_type", "authorization_code")
                .build())
            .exchange()
            .expectStatus().isFound().expectHeader()
            .value(LOCATION, value -> {
                location.set(value);
                assertTrue(value.startsWith("http://localhost:6060/login"));
            });
    }

    @Test
    void verifyJWKSEndpoint() {
        webTestClient.get()
            .uri(uriBuilder -> uriBuilder.path("/oauth2/jwks").build()).exchange().expectBody()
            .jsonPath("$.keys[0].kid").exists()
            .jsonPath("$.keys[0].n").exists()
            .jsonPath("$.keys[0].kty").isEqualTo("RSA")
            .jsonPath("$.keys[0].e").isEqualTo("AQAB");
    }

    private String getExcpectedJson() {
        return "{\n"
            + "  \"issuer\": \"http://localhost:6060\",\n"
            + "  \"authorization_endpoint\": \"http://localhost:6060/oauth2/authorize\",\n"
            + "  \"device_authorization_endpoint\": \"http://localhost:6060/oauth2/device_authorization\",\n"
            + "  \"token_endpoint\": \"http://localhost:6060/oauth2/token\",\n"
            + "  \"token_endpoint_auth_methods_supported\": [\n"
            + "    \"client_secret_basic\",\n"
            + "    \"client_secret_post\",\n"
            + "    \"client_secret_jwt\",\n"
            + "    \"private_key_jwt\"\n"
            + "  ],\n"
            + "  \"jwks_uri\": \"http://localhost:6060/oauth2/jwks\",\n"
            + "  \"response_types_supported\": [\n"
            + "    \"code\"\n"
            + "  ],\n"
            + "  \"grant_types_supported\": [\n"
            + "    \"authorization_code\",\n"
            + "    \"client_credentials\",\n"
            + "    \"refresh_token\",\n"
            + "    \"urn:ietf:params:oauth:grant-type:device_code\"\n"
            + "  ],\n"
            + "  \"revocation_endpoint\": \"http://localhost:6060/oauth2/revoke\",\n"
            + "  \"revocation_endpoint_auth_methods_supported\": [\n"
            + "    \"client_secret_basic\",\n"
            + "    \"client_secret_post\",\n"
            + "    \"client_secret_jwt\",\n"
            + "    \"private_key_jwt\"\n"
            + "  ],\n"
            + "  \"introspection_endpoint\": \"http://localhost:6060/oauth2/introspect\",\n"
            + "  \"introspection_endpoint_auth_methods_supported\": [\n"
            + "    \"client_secret_basic\",\n"
            + "    \"client_secret_post\",\n"
            + "    \"client_secret_jwt\",\n"
            + "    \"private_key_jwt\"\n"
            + "  ],\n"
            + "  \"code_challenge_methods_supported\": [\n"
            + "    \"S256\"\n"
            + "  ]\n"
            + "}";
    }
}
