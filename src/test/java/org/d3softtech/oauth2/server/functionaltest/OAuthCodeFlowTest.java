package org.d3softtech.oauth2.server.functionaltest;


import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.d3softtech.oauth2.server.functionaltest.OAuthCodeFlowTest.OAuthFlowResponse.from;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.HttpHeaders.COOKIE;
import static org.springframework.http.HttpHeaders.LOCATION;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CODE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.GRANT_TYPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.PASSWORD;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REDIRECT_URI;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.STATE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.TOKEN;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.USERNAME;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.apache.hc.core5.net.URIBuilder;
import org.d3softtech.oauth2.server.crypto.password.D3PasswordEncoder;
import org.d3softtech.oauth2.server.service.D3UserDetailsService.D3User;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;

@Slf4j
@SpringBootTest
public class OAuthCodeFlowTest {

  private static final JsonMapper JSON_MAPPER = new JsonMapper();
  public static final String TOKEN_ENDPOINT = "/oauth2/token";
  public static final String TEST_CLIENT_ID = "spring-test";
  public static final String TEST_REFERENCE_CLIENT_ID = "spring-reference";
  public static final String TEST_REDIRECT_URI = "https://127.0.0.1:9443/login/oauth2/code/spring";
  public static final String AUTHORIZE_ENDPOINT = "/oauth2/authorize";
  public static final String TEST_SCOPES = "openid profile email";
  public static final String TEST_CLIENT_SECRET = "test-secret";
  public static final String TEST_REFERENCE_CLIENT_SECRET = "R3ferenc$";
  public static final String FORM_FIELD_ATTR_NAME = "name";
  public static final String RETURN_ATTRIBUTE = "value";
  public static final String INTROSPECT_ENDPOINT = "/oauth2/introspect";
  public static final String REVOKE_ENDPOINT = "/oauth2/revoke";


  public static final String TEST_USER_NAME = "d3user";
  public static final String TEST_USER_SSN = "197611119877";
  public static final String TEST_USER_EMAIL = "test-user@d3softtech.com";
  public static final List<String> TEST_ROLES = List.of("admin", "user");
  private WebTestClient webTestClient;

  public static MockWebServer mockBackEnd;

  @Autowired
  private D3PasswordEncoder d3PasswordEncoder;

  @DynamicPropertySource
  static void properties(DynamicPropertyRegistry r) throws IOException {
    r.add("user.details.service.base.url", () -> "http://localhost:" + mockBackEnd.getPort());
  }

  @BeforeAll
  static void setUp() throws IOException {
    mockBackEnd = new MockWebServer();
    mockBackEnd.start(9080);
  }

  @AfterAll
  static void tearDown() throws IOException {
    mockBackEnd.shutdown();
  }

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
  @DisplayName("authorize-code with access_token as JWT")
  void verifyAuthorizeEndpoint_WithATAsSelfContainedJWT() throws URISyntaxException, JsonProcessingException {

    //Initiate code flow with authorize endpoint
    EntityExchangeResult<byte[]> bodyContentSpec = webTestClient.get()
        .uri(uriBuilder -> uriBuilder.path(AUTHORIZE_ENDPOINT)
            .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue())
            .queryParam(OAuth2ParameterNames.CLIENT_ID, TEST_CLIENT_ID)
            .queryParam(OAuth2ParameterNames.SCOPE, TEST_SCOPES)
            .queryParam(OAuth2ParameterNames.REDIRECT_URI, TEST_REDIRECT_URI)
            .build())
        .accept(TEXT_HTML)//Required to redirect to login page after 401 by Spring security
        .exchange()
        .expectStatus().isFound().expectBody().returnResult();
    OAuthFlowResponse firstResponse = from(bodyContentSpec, "");
    OAuthFlowResponse oAuthFlowResponse = followRedirect(firstResponse, HttpStatus.OK);
    //With consent done at first attempt it get stored and referred in subsequent attempts, therefore only first attempt will prompt user for consent unless the
    // it gets invalidated with time or according to policy

    String csrfToken = getCsrfToken(oAuthFlowResponse);

    mockUserDetailsResponseFromUserDetailsService();

    EntityExchangeResult<byte[]> bodyContentLoginResponse = webTestClient.post().uri("/login")
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(BodyInserters.fromFormData(USERNAME, "d3user")//refer application.yml
            .with(PASSWORD, "P@ssw0rd").with("_csrf", csrfToken))
        .headers(httpHeaders -> httpHeaders.add(COOKIE, oAuthFlowResponse.cookie))
        .exchange().expectStatus().isFound().expectBody().returnResult();
    OAuthFlowResponse newOAuthFlowResponse = from(bodyContentLoginResponse, oAuthFlowResponse.cookie);
    newOAuthFlowResponse = followRedirect(newOAuthFlowResponse, HttpStatus.FOUND, HttpStatus.OK);

    //If already authenticated consent response is stored and will not be rendered again until it gets invalidated
    if (newOAuthFlowResponse.httpStatus().isSameCodeAs(HttpStatus.OK)) { //Do consent if asked for

      String clientId = getFormFieldValue(newOAuthFlowResponse, FORM_FIELD_ATTR_NAME, CLIENT_ID,
          RETURN_ATTRIBUTE);
      String state = getFormFieldValue(newOAuthFlowResponse, FORM_FIELD_ATTR_NAME, STATE, RETURN_ATTRIBUTE);
      Set<String> scopes = getFormFieldValues(newOAuthFlowResponse, FORM_FIELD_ATTR_NAME, SCOPE,
          RETURN_ATTRIBUTE);

      MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
      formData.add(CLIENT_ID, clientId);
      formData.add(STATE, state);
      scopes.forEach(scope -> formData.add(SCOPE, scope));

      OAuthFlowResponse finalNewOAuthFlowResponse = newOAuthFlowResponse;
      EntityExchangeResult<byte[]> consentSubmitResponse = webTestClient.post().uri(AUTHORIZE_ENDPOINT)
          .contentType(APPLICATION_FORM_URLENCODED)
          .body(BodyInserters.fromFormData(formData))
          .headers(httpHeaders -> httpHeaders.add(COOKIE, finalNewOAuthFlowResponse.cookie))
          .exchange().expectStatus().isFound().expectBody().returnResult();

      newOAuthFlowResponse = from(consentSubmitResponse, finalNewOAuthFlowResponse.cookie);
    }

    String finalDestinationPostOAuthLogin = newOAuthFlowResponse.getRedirectionLocation();
    //Checking finally redirected to client site to exchange for code
    assertTrue(finalDestinationPostOAuthLogin.startsWith(TEST_REDIRECT_URI));
    //Let's exchange code for access and refresh token
    URIBuilder responseUriBuilder = new URIBuilder(finalDestinationPostOAuthLogin);

    log.info("The code received={}", responseUriBuilder.getFirstQueryParam(CODE).getValue());

    //Exchange code for tokens
    MultiValueMap<String, String> tokenRequestParams = new LinkedMultiValueMap<>();
    tokenRequestParams.add(GRANT_TYPE, AUTHORIZATION_CODE.getValue());
    tokenRequestParams.add(CODE, responseUriBuilder.getFirstQueryParam(CODE).getValue());
    tokenRequestParams.add(REDIRECT_URI, TEST_REDIRECT_URI);
    tokenRequestParams.add("email", TEST_USER_EMAIL);
    tokenRequestParams.add("ssn", TEST_USER_SSN);
    tokenRequestParams.add("username", TEST_USER_NAME);
    tokenRequestParams.addAll("roles", TEST_ROLES);

    Token token = webTestClient.post().uri(uriBuilder -> uriBuilder.path(TOKEN_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        //Client credentials can be provided in different ways, lets try with Basic Auth. This is RECOMMENDED way.
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_CLIENT_ID, TEST_CLIENT_SECRET))
        .body(BodyInserters.fromFormData(tokenRequestParams))
        .exchange().expectBody(Token.class).returnResult().getResponseBody();
    log.info("Tokens after successful login: {}", token);
    assertNotNull(token);
    assertNotNull(token.accessToken);
    assertNotNull(token.refreshToken);
    assertNotNull(token.idToken);
    assertNotNull(token.tokenType);
    assertEquals(TEST_SCOPES, token.scope);
    assertEquals(299, token.expiresIn);

    verifyAccessToken(token.accessToken);
    //Introspect RT
    MultiValueMap<String, String> introspectionRequestParams = new LinkedMultiValueMap<>();
    introspectionRequestParams.add(TOKEN, token.refreshToken);

    IntrospectionResponse introspectionResponse = webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(INTROSPECT_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(BodyInserters.fromFormData(introspectionRequestParams))
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_CLIENT_ID, TEST_CLIENT_SECRET)).exchange()
        .expectBody(IntrospectionResponse.class).returnResult().getResponseBody();
    log.info("RT Introspection response: {}", introspectionResponse);
    assertNotNull(introspectionResponse);
    assertTrue(introspectionResponse.active);
    assertEquals(TEST_CLIENT_ID, introspectionResponse.clientId);

    //Introspect AT
    introspectionRequestParams = new LinkedMultiValueMap<>();

    introspectionResponse = webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(INTROSPECT_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(BodyInserters.fromFormData(introspectionRequestParams))
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_CLIENT_ID, TEST_CLIENT_SECRET)).exchange()
        .expectBody(IntrospectionResponse.class).returnResult().getResponseBody();
    log.info("AT Introspection response: {}", introspectionResponse);

    //Refresh tokens
    MultiValueMap<String, String> refreshTokenRequestParams = new LinkedMultiValueMap<>();
    refreshTokenRequestParams.add(GRANT_TYPE,
        AuthorizationGrantType.REFRESH_TOKEN.getValue());
    refreshTokenRequestParams.add(OAuth2ParameterNames.REFRESH_TOKEN, token.refreshToken);
    refreshTokenRequestParams.add(OAuth2ParameterNames.SCOPE, "openid");

    Token refreshedTokens = webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(TOKEN_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_CLIENT_ID, TEST_CLIENT_SECRET))
        .body(BodyInserters.fromFormData(refreshTokenRequestParams)).exchange().expectStatus()
        .isOk().expectBody(Token.class).returnResult().getResponseBody();
    log.info("Tokens after refresh: {}", refreshedTokens);
    assertNotNull(refreshedTokens);
    assertNotEquals(token, refreshedTokens);

    //Revoke tokens
    MultiValueMap<String, String> revokeTokensRequestParams = new LinkedMultiValueMap<>();
    revokeTokensRequestParams.add(OAuth2ParameterNames.TOKEN, refreshedTokens.refreshToken);

    webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(REVOKE_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_CLIENT_ID, TEST_CLIENT_SECRET))
        .body(BodyInserters.fromFormData(revokeTokensRequestParams)).exchange().expectStatus()
        .isOk().expectBody(Void.class);

    //Introspect again
    MultiValueMap<String, String> introspectionAgainRequestParams = new LinkedMultiValueMap<>();
    introspectionAgainRequestParams.add(TOKEN, refreshedTokens.refreshToken);

    IntrospectionResponse revokeResponse = webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(INTROSPECT_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_CLIENT_ID, TEST_CLIENT_SECRET))
        .body(BodyInserters.fromFormData(introspectionAgainRequestParams)).exchange()
        .expectBody(IntrospectionResponse.class).returnResult().getResponseBody();

    log.info("Introspection response post revoke: {}", revokeResponse);

    assertNotNull(revokeResponse);
    assertFalse(revokeResponse.active);
    assertNull(revokeResponse.clientId);
    assertEquals(0, revokeResponse.issuedAt);
    assertEquals(0, revokeResponse.expireAt);
  }


  @Test
  @DisplayName("authorize-code with access_token as reference")
  void verifyAuthorizeEndpoint_WithATAsReference() throws URISyntaxException, JsonProcessingException {

    //Initiate code flow with authorize endpoint
    EntityExchangeResult<byte[]> bodyContentSpec = webTestClient.get()
        .uri(uriBuilder -> uriBuilder.path(AUTHORIZE_ENDPOINT)
            .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue())
            .queryParam(OAuth2ParameterNames.CLIENT_ID, TEST_REFERENCE_CLIENT_ID)
            .queryParam(OAuth2ParameterNames.SCOPE, TEST_SCOPES)
            .queryParam(OAuth2ParameterNames.REDIRECT_URI, TEST_REDIRECT_URI)
            .build())
        .accept(TEXT_HTML)//Required to redirect to login page after 401 by Spring security
        .exchange()
        .expectStatus().isFound().expectBody().returnResult();
    OAuthFlowResponse firstResponse = from(bodyContentSpec, "");
    OAuthFlowResponse oAuthFlowResponse = followRedirect(firstResponse, HttpStatus.OK);
    //With consent done at first attempt it get stored and referred in subsequent attempts, therefore only first attempt will prompt user for consent unless the
    // it gets invalidated with time or according to policy

    String csrfToken = getCsrfToken(oAuthFlowResponse);

    mockUserDetailsResponseFromUserDetailsService();

    EntityExchangeResult<byte[]> bodyContentLoginResponse = webTestClient.post().uri("/login")
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(BodyInserters.fromFormData(USERNAME, "d3user")//refer application.yml
            .with(PASSWORD, "P@ssw0rd").with("_csrf", csrfToken))
        .headers(httpHeaders -> httpHeaders.add(COOKIE, oAuthFlowResponse.cookie))
        .exchange().expectStatus().isFound().expectBody().returnResult();
    OAuthFlowResponse newOAuthFlowResponse = from(bodyContentLoginResponse, oAuthFlowResponse.cookie);
    newOAuthFlowResponse = followRedirect(newOAuthFlowResponse, HttpStatus.FOUND, HttpStatus.OK);

    String finalDestinationPostOAuthLogin = newOAuthFlowResponse.getRedirectionLocation();
    //Checking finally redirected to client site to exchange for code
    assertTrue(finalDestinationPostOAuthLogin.startsWith(TEST_REDIRECT_URI));
    //Let's exchange code for access and refresh token
    URIBuilder responseUriBuilder = new URIBuilder(finalDestinationPostOAuthLogin);

    log.info("The code received={}", responseUriBuilder.getFirstQueryParam(CODE).getValue());

    //Exchange code for tokens
    MultiValueMap<String, String> tokenRequestParams = new LinkedMultiValueMap<>();
    tokenRequestParams.add(GRANT_TYPE, AUTHORIZATION_CODE.getValue());
    tokenRequestParams.add(CODE, responseUriBuilder.getFirstQueryParam(CODE).getValue());
    tokenRequestParams.add(REDIRECT_URI, TEST_REDIRECT_URI);
    tokenRequestParams.add("email", TEST_USER_EMAIL);
    tokenRequestParams.add("ssn", TEST_USER_SSN);
    tokenRequestParams.add("username", TEST_USER_NAME);
    tokenRequestParams.addAll("roles", TEST_ROLES);

    Token token = webTestClient.post().uri(uriBuilder -> uriBuilder.path(TOKEN_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        //Client credentials can be provided in different ways, lets try with Basic Auth. This is RECOMMENDED way.
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_REFERENCE_CLIENT_ID, TEST_REFERENCE_CLIENT_SECRET))
        .body(BodyInserters.fromFormData(tokenRequestParams))
        .exchange().expectBody(Token.class).returnResult().getResponseBody();
    log.info("Tokens after successful login: {}", token);
    assertNotNull(token);
    assertNotNull(token.accessToken);
    assertNotNull(token.refreshToken);
    assertNotNull(token.idToken);
    assertNotNull(token.tokenType);
    assertEquals(TEST_SCOPES, token.scope);
    assertEquals(299, token.expiresIn);

    verifyAccessTokenIsReference(token.accessToken);
    //Introspect RT
    MultiValueMap<String, String> introspectionRequestParams = new LinkedMultiValueMap<>();
    introspectionRequestParams.add(TOKEN, token.refreshToken);

    IntrospectionResponse introspectionResponse = webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(INTROSPECT_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        .accept(APPLICATION_JSON)
        .body(BodyInserters.fromFormData(introspectionRequestParams))
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_REFERENCE_CLIENT_ID, TEST_REFERENCE_CLIENT_SECRET))
        .exchange()
        .expectBody(IntrospectionResponse.class).returnResult().getResponseBody();
    log.info("RT Introspection response: {}", introspectionResponse);
    assertNotNull(introspectionResponse);
    assertTrue(introspectionResponse.active);
    assertEquals(TEST_REFERENCE_CLIENT_ID, introspectionResponse.clientId);

    //Introspect AT
    introspectionRequestParams = new LinkedMultiValueMap<>();
    introspectionRequestParams.add(TOKEN, token.accessToken);
    OpaqueTokenIntrospectionResponse opaqueTokenIntrospectionResponse = webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(INTROSPECT_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(BodyInserters.fromFormData(introspectionRequestParams))
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_REFERENCE_CLIENT_ID, TEST_REFERENCE_CLIENT_SECRET))
        .exchange()
        .expectBody(OpaqueTokenIntrospectionResponse.class).returnResult().getResponseBody();
    log.info("AT Introspection response: {}", opaqueTokenIntrospectionResponse);

    //Refresh tokens
    MultiValueMap<String, String> refreshTokenRequestParams = new LinkedMultiValueMap<>();
    refreshTokenRequestParams.add(GRANT_TYPE,
        AuthorizationGrantType.REFRESH_TOKEN.getValue());
    refreshTokenRequestParams.add(OAuth2ParameterNames.REFRESH_TOKEN, token.refreshToken);
    refreshTokenRequestParams.add(OAuth2ParameterNames.SCOPE, "openid");

    Token refreshedTokens = webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(TOKEN_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_REFERENCE_CLIENT_ID, TEST_REFERENCE_CLIENT_SECRET))
        .body(BodyInserters.fromFormData(refreshTokenRequestParams)).exchange().expectStatus()
        .isOk().expectBody(Token.class).returnResult().getResponseBody();
    log.info("Tokens after refresh: {}", refreshedTokens);
    assertNotNull(refreshedTokens);
    assertNotEquals(token, refreshedTokens);

    //Revoke tokens
    MultiValueMap<String, String> revokeTokensRequestParams = new LinkedMultiValueMap<>();
    revokeTokensRequestParams.add(OAuth2ParameterNames.TOKEN, refreshedTokens.refreshToken);

    webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(REVOKE_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_REFERENCE_CLIENT_ID, TEST_REFERENCE_CLIENT_SECRET))
        .body(BodyInserters.fromFormData(revokeTokensRequestParams)).exchange().expectStatus()
        .isOk().expectBody(Void.class);

    //Introspect again
    MultiValueMap<String, String> introspectionAgainRequestParams = new LinkedMultiValueMap<>();
    introspectionAgainRequestParams.add(TOKEN, refreshedTokens.refreshToken);

    IntrospectionResponse revokeResponse = webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(INTROSPECT_ENDPOINT).build())
        .contentType(APPLICATION_FORM_URLENCODED)
        .headers(httpHeaders -> httpHeaders.setBasicAuth(TEST_REFERENCE_CLIENT_ID, TEST_REFERENCE_CLIENT_SECRET))
        .body(BodyInserters.fromFormData(introspectionAgainRequestParams)).exchange()
        .expectBody(IntrospectionResponse.class).returnResult().getResponseBody();

    log.info("Introspection response post revoke: {}", revokeResponse);

    assertNotNull(revokeResponse);
    assertFalse(revokeResponse.active);
    assertNull(revokeResponse.clientId);
    assertEquals(0, revokeResponse.issuedAt);
    assertEquals(0, revokeResponse.expireAt);
  }

  private void verifyAccessTokenIsReference(String accessToken) {
    assertFalse(accessToken.contains("."));
  }

  private void mockUserDetailsResponseFromUserDetailsService() throws JsonProcessingException {
    D3User d3UserFromService = D3User.builder()
        .userId(123)
        .ssn(TEST_USER_SSN)
        .email(TEST_USER_EMAIL)
        .roles(TEST_ROLES)
        .password(d3PasswordEncoder.encode("P@ssw0rd"))
        .isPasswordChangeRequired(true)
        .username(TEST_USER_NAME).build();
    mockBackEnd.enqueue(new MockResponse().setResponseCode(HttpStatus.OK.value())
        .setBody(JSON_MAPPER.writeValueAsString(d3UserFromService))
        .addHeader("Content-Type", "application/json"));
  }

  private void verifyAccessToken(Object accessToken) {
    try {
      JWT jwt = JWTParser.parse((String) accessToken);
      assertEquals(TEST_USER_SSN, jwt.getJWTClaimsSet().getStringClaim("ssn"));
      assertTrue(List.of("admin", "user").containsAll(jwt.getJWTClaimsSet().getStringListClaim("roles")));
      assertEquals(TEST_USER_EMAIL, jwt.getJWTClaimsSet().getStringClaim("email"));
      assertEquals(TEST_USER_NAME, jwt.getJWTClaimsSet().getStringClaim("username"));
    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
  }

  private String getCsrfToken(OAuthFlowResponse oAuthFlowResponse) {
    String loginForm = oAuthFlowResponse.getResponseBody();
    Document doc = Jsoup.parse(loginForm);
    Elements elements = doc.getElementsByAttributeValue("name", "_csrf");
    return elements.get(0).attr("value");
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
    if (location.indexOf("?error") > 0) {

      log.error(location);
      throw new RuntimeException("There was an error!!");
    }

    log.info("following redirect at {} and cookie={}", location.replace("%20", " "), oAuthFlowResponse.cookie);
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

  @JsonIgnoreProperties(ignoreUnknown = true)
  record IntrospectionResponse(boolean active, @JsonProperty("client_id") String clientId,
                               @JsonProperty("iat") long issuedAt, @JsonProperty("exp") long expireAt) {

  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  record OpaqueTokenIntrospectionResponse(boolean active, @JsonProperty("client_id") String clientId,
                                          @JsonProperty("sub") String subject, @JsonProperty("scope") String scope,
                                          @JsonProperty("iss") String issuer,
                                          @JsonProperty("aud") List<String> audience,
                                          @JsonProperty("token_type") String tokenType,
                                          @JsonProperty("iat") long issuedAt,
                                          @JsonProperty("nbf") long notBefore, @JsonProperty("exp") long expireAt) {

  }

}
