I wrote previously about default configuration(branch [Default Config](https://github.com/naveen-maanju/spring-oauth2-server/tree/Default-Config)) of Spring oauth-authorization-server. Now lets jump
into, how we can customize it to suite our requirements. Starting with, in this article we will
discuss on how we can customize the JWT token claims with default configurations (though you can
change as per your requirement).

The default access_token claims are:

```json

{
  "iss": "http://localhost:6060",
  "sub": "spring-test",
  "aud": "spring-test",
  "nbf": 1697183856,
  "exp": 1697184156,
  "iat": 1697183856
}
```

and after customization with additional claims(roles, email, ssn and username) it looks like:

```json
{
  "sub": "spring-test",
  "aud": "spring-test",
  "nbf": 1699198349,
  "roles": [
    "admin",
    "user"
  ],
  "iss": "http://localhost:6060",
  "exp": 1699198649,
  "iat": 1699198349,
  "client_id": "spring-test",
  "email": "test-user@d3softtech.com",
  "ssn": "197611119877",
  "username": "test-user"
}
```

Let's see how we can achieve that in spring authorization server.

Spring provides OAuth2TokenCustomizer<T extends OAuth2TokenContext> interface (FunctionalInterface)
to customize the OAuth2Token which can be used to customize any token issued by spring oauth-server.

```java

@FunctionalInterface
public interface OAuth2TokenCustomizer<T extends OAuth2TokenContext> {

  /**
   * Customize the OAuth 2.0 Token attributes.
   *
   * @param context the context containing the OAuth 2.0 Token attributes
   */
  void customize(T context);

}
```

Therefore in order to provide the customizer to spring context, define a bean using configuration.
You can define one or more Customizer to support different token flows.

## Single Customizer

If there is requirement to customize token for a single flow, it can be defined with Customizer as a
bean like below for client-credential (grant-type) token.

```java

@Configuration
public class AuthorizationServerConfiguration {

  @Bean
  protected OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
    return jwtContext -> {
      if (CLIENT_CREDENTIALS.equals(jwtContext.getAuthorizationGrantType()) && ACCESS_TOKEN.equals(
          jwtContext.getTokenType())) {
        OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = jwtContext.getAuthorizationGrant();
        Map<String, Object> additionalParameters = clientCredentialsAuthentication.getAdditionalParameters();
        additionalParameters.forEach((key, value) -> jwtContext.getClaims().claim(key, value));
      }
    };
  }
}
```

Additional parameters can be provided as the query param or as a body like

### Query param

In test (
refer [AuthorizationServerTest.verifyTokenEndpoint_WithAdditionParamsAsQueryParam](./src/test/java/org/d3softtech/oauth2/server/AuthorizationServerTest.java))

```java
  @Test
  void verifyTokenEndpoint_WithAdditionParamsAsQueryParam(){
      webTestClient.post()
      .uri(uriBuilder->uriBuilder.path("/oauth2/token").queryParam("grant_type","client_credentials")
      .queryParam("email",TEST_USER_EMAIL).queryParam("ssn",TEST_USER_SSN)
      .queryParam("username",TEST_USER_NAME).queryParam("roles",Set.of("admin","user")).build())
      .headers(httpHeaders->httpHeaders.setBasicAuth("spring-test","test-secret")).exchange()
      .expectStatus().isOk()
      .expectBody()
      .jsonPath("$.access_token").value(this::verifyAccessToken)
      .jsonPath("$.token_type").isEqualTo("Bearer")
      .jsonPath("$.expires_in").isEqualTo(299);
      }

private void verifyAccessToken(Object accessToken){
    try{
    JWT jwt=JWTParser.parse((String)accessToken);
    assertEquals(TEST_USER_SSN,jwt.getJWTClaimsSet().getStringClaim("ssn"));
    assertTrue(List.of("admin","user").containsAll(jwt.getJWTClaimsSet().getStringListClaim("roles")));
    assertEquals(TEST_USER_EMAIL,jwt.getJWTClaimsSet().getStringClaim("email"));
    assertEquals(TEST_USER_NAME,jwt.getJWTClaimsSet().getStringClaim("username"));
    }catch(ParseException e){
    throw new RuntimeException(e);
    }
    }
```

In the example above, a POST request is used to invoke the /oauth2/token endpoint of the
authorization server, to get the access-token. The minimum parameters required by the authorization
server are:

1. grant_type
2. client_id (as header)
3. client_secret (as header)

and all the other parameters are additional parameters that you can provide to customize the
access_token. As in the above example we have added email, ssn, username and roles as additional
parameters.

### Body Param

In test (refer AuthorizationServerTest.verifyTokenEndpoint_WithAdditionParamsAsBody())

``` java
  @Test
  void verifyTokenEndpoint_WithAdditionParamsAsBody() {
    MultiValueMap<String, Object> tokenRequestParams = new LinkedMultiValueMap<>();
    tokenRequestParams.add(GRANT_TYPE, CLIENT_CREDENTIALS.getValue());
    tokenRequestParams.add("email", TEST_USER_EMAIL);
    tokenRequestParams.add("ssn", TEST_USER_SSN);
    tokenRequestParams.add("username", TEST_USER_NAME);
    tokenRequestParams.addAll("roles", TEST_ROLES);

    webTestClient.post()
        .uri(uriBuilder -> uriBuilder.path(TOKEN_ENDPOINT).build())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .body(BodyInserters.fromMultipartData(tokenRequestParams))
        .headers(httpHeaders -> httpHeaders.setBasicAuth("spring-test", "test-secret"))
        .exchange()
        .expectStatus().isOk()
        .expectBody()
        .jsonPath("$.access_token").value(this::verifyAccessToken)
        .jsonPath("$.token_type").isEqualTo("Bearer")
        .jsonPath("$.expires_in").isEqualTo(299);


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

```

Parameters to oauth2/token endpoint can be provided as body to POST request. In the above example
client_id and client_secret were passed as basic auth header, and in the this case as body param.

## Multiple Customizer

If there is a need to customize the token for multiple flows, we can take the approach of delegate
customizer. The delegate customizer will delegate the request to all custom customizers defined, and
therefore token will be customized by the one or more who is responsible for through filter criteria
defined in that customizer.

Let's take an example where we want to customize the token for client-credentials and code flow. To
do so, we will first define a delegate customizer as:

```java
@Component
public class OAuth2TokenCustomizerDelegate implements OAuth2TokenCustomizer<JwtEncodingContext> {

  private List<OAuth2TokenCustomizer<JwtEncodingContext>> oAuth2TokenCustomizers;

  public OAuth2TokenCustomizerDelegate() {
    oAuth2TokenCustomizers = List.of(
      new OAuth2AuthorizationCodeTokenCustomizer(),
      new OAuth2ClientCredentialsTokenCustomizer());
  }

  @Override
  public void customize(JwtEncodingContext context) {
    oAuth2TokenCustomizers.forEach(tokenCustomizer -> tokenCustomizer.customize(context));
  }
}
```

As, the delegate customizer is defined as component, it will be consumed by spring as a bean and
will be added to application context as OAuth2TokenCustomizer . With every request for token
creation request will be delegated to this customizer to customize.

Now we can define our own custtomizers who will customize according to our needs.

### Client-Credentials Token Customizer

```java
public class OAuth2ClientCredentialsTokenCustomizer implements
OAuth2TokenCustomizer<JwtEncodingContext> {

  @Override
  public void customize(JwtEncodingContext jwtContext) {
    if (CLIENT_CREDENTIALS.equals(jwtContext.getAuthorizationGrantType()) && ACCESS_TOKEN.equals(
        jwtContext.getTokenType())) {
        OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication =
        jwtContext.getAuthorizationGrant();
        Map<String, Object> additionalParameters =
        clientCredentialsAuthentication.getAdditionalParameters();
        additionalParameters.forEach((key, value) -> jwtContext.getClaims().claim(key, value));
    }
  }
}
```

`OAuth2ClientCredentialsTokenCustomizer` will be responsible for client-credential grant-type (flow).
It will check for if the request needs to be handled or not with checking the grant-type and
token-type.

### Authorization-Code Token Customizer

```java
public class OAuth2AuthorizationCodeTokenCustomizer implements
OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext jwtContext) {
        if (AUTHORIZATION_CODE.equals(jwtContext.getAuthorizationGrantType()) && ACCESS_TOKEN.equals(
            jwtContext.getTokenType())) {
            OAuth2AuthorizationCodeAuthenticationToken oAuth2AuthorizationCodeAuthenticationToken =
            jwtContext.getAuthorizationGrant();
            Map<String, Object> additionalParameters =
            oAuth2AuthorizationCodeAuthenticationToken.getAdditionalParameters();
            additionalParameters.forEach((key, value) -> jwtContext.getClaims().claim(key, value));
        }
    }
}
```

OAuth2AuthorizationCodeTokenCustomizer will be responsible as name suggest for authorization-code
grant-type (code flow).

## Test

The functional test class AuthorizationServerTest, have steps on how to

1. initiate the code flow with authorize endpoint with required parameters.
2. authenticate the user
3. Collect code after successful authentication
4. Exchange code for Tokens
5. Introspect token
6. Refresh token
7. Revoke tokens
8. Introspect post revocation

Hope this help you in customizing the tokens.  

