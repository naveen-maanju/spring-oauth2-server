package org.d3softtech.oauth2.server.functionaltest;


import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.d3softtech.oauth2.server.functionaltest.OAuthCodeFlowTest.OAuthFlowResponse.from;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.COOKIE;
import static org.springframework.http.HttpHeaders.LOCATION;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.net.URIBuilder;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;

@Slf4j
@SpringBootTest
public class OAuthCodeFlowTest {

    private WebTestClient webTestClient;

    private static <T> String getCookie(EntityExchangeResult<T> bodyContentSpec, String existingCookie) {
        HttpHeaders responseHeaders = bodyContentSpec.getResponseHeaders();
        return Optional.ofNullable(responseHeaders.get("Set-Cookie")).map(cookieList -> cookieList.get(0))
            .orElse(existingCookie);
    }

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
    void verifyAuthorizeEndpoint() throws URISyntaxException {

        //Initiate code flow with authorize endpoint
        EntityExchangeResult<byte[]> bodyContentSpec = webTestClient.get()
            .uri(uriBuilder -> uriBuilder.path("/oauth2/authorize").queryParam("response_type", "code")
                .queryParam("client_id", "spring-test").queryParam("scope", "openid profile email")
                .queryParam("redirect_uri", "https://127.0.0.1:9443/login/oauth2/code/spring")
                .build())
            .header(ACCEPT, TEXT_HTML_VALUE)//Required to redirect to login page after 401 by Spring security
            .exchange()
            .expectStatus().isFound().expectBody().returnResult();
        OAuthFlowResponse firstResponse = from(bodyContentSpec, "");
        OAuthFlowResponse oAuthFlowResponse = followRedirect(firstResponse, HttpStatus.OK);

        //With consent done at first attempt it get stored and referred in subsequent attempts, therefore only first attempt will prompt user for consent unless the
        // it gets invalidated with time or according to policy

        String csrfToken = getCsrfToken(oAuthFlowResponse);
        EntityExchangeResult<byte[]> bodyContentLoginResponse = webTestClient.post().uri("/login")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData("username", "Operator123")
                .with("password", "P@ssw0rd").with("_csrf", csrfToken))
            .headers(httpHeaders -> httpHeaders.add(COOKIE, oAuthFlowResponse.cookie))
            .exchange().expectStatus().isFound().expectBody().returnResult();
        OAuthFlowResponse newOAuthFlowResponse = from(bodyContentLoginResponse, oAuthFlowResponse.cookie);
        newOAuthFlowResponse = followRedirect(newOAuthFlowResponse, HttpStatus.FOUND, HttpStatus.OK);

        //If already authenticated consent response is stored and will not be rendered again until it gets invalidated
        if (newOAuthFlowResponse.httpStatus().isSameCodeAs(HttpStatus.OK)) {

            String clientId = getFormFieldValue(newOAuthFlowResponse, "name", "client_id", "value");
            String state = getFormFieldValue(newOAuthFlowResponse, "name", "state", "value");
            Set<String> scopes = getFormFieldValues(newOAuthFlowResponse, "name", "scope", "value");

            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("client_id", clientId);
            formData.add("state", state);
            scopes.forEach(scope -> formData.add("scope", scope));

            OAuthFlowResponse finalNewOAuthFlowResponse = newOAuthFlowResponse;
            EntityExchangeResult<byte[]> consentSubmitResponse = webTestClient.post().uri("/oauth2/authorize")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formData))
                .headers(httpHeaders -> httpHeaders.add(COOKIE, finalNewOAuthFlowResponse.cookie))
                .exchange().expectStatus().isFound().expectBody().returnResult();

            newOAuthFlowResponse = from(consentSubmitResponse, finalNewOAuthFlowResponse.cookie);
        }

        String finalDestinationPostOAuthLogin = newOAuthFlowResponse.getRedirectionLocation();
        //Checking finally redirected to client site to exchange for code
        assertTrue(finalDestinationPostOAuthLogin.startsWith("https://127.0.0.1:9443/login/oauth2/code/spring?code="));
        //Let's exchange code for access and refresh token
        URIBuilder responseUriBuilder = new URIBuilder(finalDestinationPostOAuthLogin);

        log.info("The code received={}", responseUriBuilder.getFirstQueryParam("code").getValue());
        Token token = webTestClient.post().uri(
                uriBuilder -> uriBuilder.path("/oauth2/token").queryParam("grant_type", "authorization_code")
                    .queryParam("code", responseUriBuilder.getFirstQueryParam("code").getValue())
                    .queryParam("redirect_uri", "https://127.0.0.1:9443/login/oauth2/code/spring").build())
            .headers(httpHeaders -> httpHeaders.setBasicAuth("spring-test", "test-secret"))
            .exchange().expectBody(Token.class).returnResult().getResponseBody();
        assertNotNull(token);
        assertNotNull(token.accessToken);
        assertNotNull(token.refreshToken);
        assertNotNull(token.idToken);
        assertNotNull(token.tokenType);
        assertEquals("openid profile email", token.scope);
        assertEquals(299, token.expiresIn);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", token.refreshToken);

        IntrospectionResponse introspectionResponse= webTestClient.post().uri(uriBuilder -> uriBuilder.path("/oauth2/introspect").build())
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData(formData))
            .headers(httpHeaders -> httpHeaders.setBasicAuth("spring-test", "test-secret")).exchange()
            .expectBody(IntrospectionResponse.class).returnResult().getResponseBody();
        assertNotNull(introspectionResponse);
        assertTrue(introspectionResponse.active);
        assertEquals("spring-test",introspectionResponse.clientId);



    }

    private String getCsrfToken(OAuthFlowResponse oAuthFlowResponse) {
        String loginForm = oAuthFlowResponse.getResponseBody();
        Document doc = Jsoup.parse(loginForm);
        Elements elements = doc.getElementsByAttributeValue("name", "_csrf");
        String csrfToken = elements.get(0).attr("value");
        return csrfToken;
    }

    private String getFormFieldValue(OAuthFlowResponse consentFormResponse, String key, String value,
        String returnAttribute) {
        return getFormFieldValue(consentFormResponse.getResponseBody(), key, value, returnAttribute);
    }

    private String getFormFieldValue(String htmlResponse, String key, String value,
        String returnAttribute) {
        Document htmlDoc = Jsoup.parse(htmlResponse);
        Elements elements = htmlDoc.getElementsByAttributeValue(key, value);
        return elements.get(0).attr(returnAttribute);
    }

    private Set<String> getFormFieldValues(OAuthFlowResponse consentFormResponse, String key, String value,
        String returnAttribute) {
        Set<String> formFieldValues = new HashSet<>();
        String htmlResponse = consentFormResponse.getResponseBody();
        Document htmlDoc = Jsoup.parse(htmlResponse);
        Elements elements = htmlDoc.getElementsByAttributeValue(key, value);
        elements.forEach(element -> formFieldValues.add(element.attr(returnAttribute)));
        return formFieldValues;
    }

    private OAuthFlowResponse followRedirect(OAuthFlowResponse oAuthFlowResponse,
        HttpStatus... httpStatus) {
        if (!oAuthFlowResponse.httpStatus.isSameCodeAs(HttpStatus.FOUND)) {
            throw new RuntimeException(format("In valid status for following redirect! Expected 302 but found=%d",
                oAuthFlowResponse.httpStatus));
        }
        String location = oAuthFlowResponse.getRedirectionLocation();
        log.info("following redirect at {} and cookie={}", location, oAuthFlowResponse.cookie);
        URI redirectUri = URI.create(location);
        log.info("The path will be {}", redirectUri.getPath());
        EntityExchangeResult<byte[]> response = webTestClient.get()
            .uri(uriBuilder -> uriBuilder.path(redirectUri.getPath()).query(redirectUri.getQuery()).build())
            .headers(httpHeaders -> httpHeaders.add(COOKIE, oAuthFlowResponse.cookie))
            .exchange().expectStatus().value(value -> assertThat(httpStatus).contains(HttpStatus.valueOf(value)))
            .expectBody()
            .returnResult();

        return from(response, oAuthFlowResponse.cookie);
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

    @Builder
    record OAuthFlowResponse(HttpHeaders responseHeaders, byte[] body, HttpStatus httpStatus, String cookie) {

        public static OAuthFlowResponse from(EntityExchangeResult<byte[]> response, String cookie) {
            return OAuthFlowResponse.builder().responseHeaders(response.getResponseHeaders())
                .body(response.getResponseBody()).httpStatus(HttpStatus.valueOf(response.getStatus().value()))
                .cookie(getCookie(response, cookie)).build();
        }

        public String getRedirectionLocation() {
            return responseHeaders.get(LOCATION).get(0);
        }

        public String getResponseBody() {
            return new String(body);
        }
    }

    record Token(@JsonProperty("access_token") String accessToken, @JsonProperty("refresh_token") String refreshToken,
                 @JsonProperty("scope") String scope, @JsonProperty("id_token") String idToken,
                 @JsonProperty("token_type") String tokenType, @JsonProperty("expires_in") int expiresIn) {

    }

    record IntrospectionResponse(boolean active, @JsonProperty("client_id") String clientId,
                                 @JsonProperty("iat") long issuedAt, @JsonProperty("exp") long expireAt) {

    }
}
