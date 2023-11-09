### About Branch

In this branch POC, we will see how we can customize the authentication, where user details are
fetched from another component/service over http. Store user details as Principal and use them later
while creating token to customize the claims in JWT(Scope of this article is two flows only -
client-credentials and code flow).

To achieve this, below changes would be required.

1. [Password encoder](#password-encoder)
2. [Service/Client to fetch user details from a service](#serviceclient-to-fetch-userdetails)
3. [UserDetails entity](#userdetails-entity)
4. [Token customizers](#token-customizers)

### Password Encoder

A password encoder is required to encode the password provided while authentication/login to
verify/validate the secret against the one stored in DB (while registration or change password) as
encoded.

Refer [D3PasswordEncoder](./src/main/java/org/d3softtech/oauth2/server/crypto/password/D3PasswordEncoder.java)

### Service/Client to fetch UserDetails

A bean/service is required to provide the custom UserDetails, this service can provide user details
as a hard-coded, from in memory storage or by calling another service. In this example we will focus
on invoking another service(user-detail-service).

The user detail service bean in oauth-server implements the UserDetailsService provided by
spring-security (as oauth-server is built on top of spring-security).

```java

@Service
public class D3UserDetailsService implements UserDetailsService {

  private final WebClient webClient;

  public D3UserDetailsService(
      @Value("${user.details.service.base.url}") String userServiceBaseUrl) {
    webClient = WebClient.builder().baseUrl(userServiceBaseUrl).build();

  }

  public UserDetails loadUserByUsername(String username) {
    D3User user = webClient.get()
        .uri(uriBuilder -> uriBuilder.path("/users").path("/{username}").build(username))
        .retrieve()
        .onStatus(httpStatusCode -> httpStatusCode.isSameCodeAs(HttpStatus.NOT_FOUND),
            clientResponse -> Mono.error(new D3Exception("Bad credentials")))
        .bodyToMono(D3User.class).block(
            Duration.ofSeconds(2));

    return new D3UserDetails(user.userId(), user.username(), user.password(),
        getAuthorities(user.roles()), user.ssn(),
        user.email(), user.isPasswordChangeRequired(), user.roles());
  }


  private List<GrantedAuthority> getAuthorities(List<String> roles) {
    List<GrantedAuthority> authorities = new ArrayList<>(roles.size());
    for (String role : roles) {
      authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
    }
    return authorities;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  @Builder
  public record D3User(@JsonProperty("id") Integer userId,
                       @JsonProperty("userName") String username,
                       String password, List<String> roles, String ssn, String email,
                       boolean isPasswordChangeRequired) {

  }

}
```

### UserDetails Entity

A UserDetails entity can (not must, unless you want to add a few more details to the authenticated
user's context)  be defined as

```java

@Getter
public class D3UserDetails extends User {

  private final Integer userId;
  private final boolean isPasswordChangeRequired;
  private final List<String> roles;
  private final String ssn;
  private final String email;

  public D3UserDetails(Integer userId, String username, String password,
      List<GrantedAuthority> authorities,
      String ssn, String email, boolean isPasswordChangeRequired, List<String> roles) {
    super(username, password, authorities);
    this.userId = userId;
    this.ssn = ssn;
    this.email = email;
    this.isPasswordChangeRequired = isPasswordChangeRequired;
    this.roles = roles;
  }
}
```

This D3UserDetails entity extends the spring security User entity and provides additional attributes
as well.

### Token Customizers

Token customizers are required to provide additional attributes/claims for access_token:

#### Self-Contained JWT token:

If the access_token format is `self-contained` then a customizer
implementing `Auth2TokenCustomizer<JwtEncodingContext>` is required.

```java
public class OAuth2JWTTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

  private static final Consumer<JwtEncodingContext> AUTHORIZE_CODE_FLOW_CUSTOMIZER = (jwtContext) -> {
    if (AUTHORIZATION_CODE.equals(jwtContext.getAuthorizationGrantType()) && ACCESS_TOKEN.equals(
        jwtContext.getTokenType())) {
      UsernamePasswordAuthenticationToken authenticatedUserToken = jwtContext.getPrincipal();
      D3UserDetails userDetails = (D3UserDetails) authenticatedUserToken.getPrincipal();
      Map.of("userId", userDetails.getUserId(),
              "username", userDetails.getUsername(),
              "isPasswordChangeRequired", userDetails.isPasswordChangeRequired(),
              "roles", userDetails.getRoles(),
              "ssn", userDetails.getSsn(),
              "email", userDetails.getEmail())
          .forEach((key, value) -> jwtContext.getClaims().claim(key, value));
    }
  };

  private static final Consumer<JwtEncodingContext> CLIENT_CREDENTIALS_FLOW_CUSTOMIZER = (jwtContext) -> {
    if (CLIENT_CREDENTIALS.equals(jwtContext.getAuthorizationGrantType()) && ACCESS_TOKEN.equals(
        jwtContext.getTokenType())) {
      OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = jwtContext.getAuthorizationGrant();
      Map<String, Object> additionalParameters = clientCredentialsAuthentication.getAdditionalParameters();
      additionalParameters.forEach((key, value) -> jwtContext.getClaims().claim(key, value));
    }
  };

  private final Consumer<JwtEncodingContext> jwtEncodingContextCustomizers = AUTHORIZE_CODE_FLOW_CUSTOMIZER.andThen(
      CLIENT_CREDENTIALS_FLOW_CUSTOMIZER);

  @Override
  public void customize(JwtEncodingContext context) {
    jwtEncodingContextCustomizers.accept(context);
  }
}
```

As the client-credential flow is always self-contained, we have to add support for it in JWTToken
along with code flow. In the case of code flow, we authenticate the user, and use the user details
fetched from UserService as additional claims in JWT. Whereas in the case of client-credentials flow
additional parameters are provided as request parameters.

#### Opaque token:

If the access_token format is `reference` then a customizer
implementing `OAuth2TokenCustomizer<OAuth2TokenClaimsContext>` is required.

```java

@Component
public class OAuth2OpaqueTokenIntrospectionResponseCustomizer implements
    OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {

  private static final Consumer<OAuth2TokenClaimsContext> INTROSPECTION_TOKEN_CLAIMS_CUSTOMIZER = (claimsContext) -> {
    if (AUTHORIZATION_CODE.equals(claimsContext.getAuthorizationGrantType()) && ACCESS_TOKEN.equals(
        claimsContext.getTokenType())) {
      UsernamePasswordAuthenticationToken authenticatedUserToken = claimsContext.getPrincipal();
      D3UserDetails userDetails = (D3UserDetails) authenticatedUserToken.getPrincipal();
      Map.of("userId", userDetails.getUserId(),
              "username", userDetails.getUsername(),
              "isPasswordChangeRequired", userDetails.isPasswordChangeRequired(),
              "roles", userDetails.getRoles(),
              "ssn", userDetails.getSsn(),
              "email", userDetails.getEmail())
          .forEach((key, value) -> claimsContext.getClaims().claim(key, value));
    }
  };

  private final Consumer<OAuth2TokenClaimsContext> claimsContextCustomizer = INTROSPECTION_TOKEN_CLAIMS_CUSTOMIZER;

  @Override
  public void customize(OAuth2TokenClaimsContext jwtContext) {
    claimsContextCustomizer.accept(jwtContext);
  }
}
```

As the reference token is associated with code flow and after successful authentication when code is
exchanged for token, the access_token so issued by authorization server will not JWT but a
reference. This reference should be exchanged for access_token with user details claims and other
claims using the introspection endpoint. A working function test can be
referred [here](./src/test/java/org/d3softtech/oauth2/server/functionaltest/OAuthCodeFlowTest.java).

In the case of self-contained, at the end of code flow, the access_token will be in the form JWT
with all additional claim including UserDetails added through customizer. Where as in the case of
opaque token (reference) an introspection call is required to fetch the UserDetails in the form of
claims in the response.

## How the response look like?

You can verify it through the test added at GitHub, it has two test methods covering both the
scenarios.

### Self-Contained JWT:

#### Code flow token response

```json
{
  "access_token": "eyJraWQiOiIxNzdjMzA1MC1lMGY2LTQ4NDctYjJiNy02NTY2ZDVlZGZiMWUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkM3VzZXIiLCJyb2xlcyI6WyJhZG1pbiIsInVzZXIiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo2MDYwIiwiaXNQYXNzd29yZENoYW5nZVJlcXVpcmVkIjp0cnVlLCJ1c2VySWQiOjEyMywic3NuIjoiMTk3NjExMTE5ODc3IiwiYXVkIjoic3ByaW5nLXRlc3QiLCJuYmYiOjE2OTkzNDcyODMsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJlbWFpbCJdLCJleHAiOjE2OTkzNDc1ODMsImlhdCI6MTY5OTM0NzI4MywiZW1haWwiOiJ0ZXN0LXVzZXJAZDNzb2Z0dGVjaC5jb20iLCJ1c2VybmFtZSI6ImQzdXNlciJ9.RQiLWmGf9_rV4UfKzKomEhuJrncG08a2F34mN-gPDw7vK2csRPGMMDRYh2Gm0Eh-n3JRTaJ9_twdPQG9BgQifKiubPsM_etxpxKLLfQHoTfqzguiP8D53FyXLB9xwhvAgKH0KWLOSRxl-bdZsctpVZpqrMTPZtfdlt7tqcl71tGDY-7Nri76Kod39kyVcKEAuLNNZKt4fhn8tCLUA64jKfmKPM3afmAdvf0PlEwgwqhGhojxtCLnYNtzuO_VQheTaQvZxrzcXw3gNRnO4vppedAyG1gmUV44l4u7cXdhG-vGc1ItU45PSg3EaG7BtHU1axKu3qHB8C7mHAhk3zVuUA",
  "refresh_token": "t9U3CDejVC2k_eNtyvM23RTN3ePpS9x8b8_pVrD-U-ivLij0dWt9NZVO9wn-kIsyr89Yj-fBFpH8BFZoMUIqGI_wZSmKgYqpO0SmNE-C1_hW8DVLqT8zQ7PkhF_Gil7N",
  "scope": "openid profile email",
  "token_type": "Bearer",
  "expires_in": 299
}
```

AccessToken JWT claims will look like:

```json
{
  "sub": "d3user",
  "roles": [
    "admin",
    "user"
  ],
  "iss": "http://localhost:6060",
  "isPasswordChangeRequired": true,
  "userId": 123,
  "ssn": "197611119877",
  "aud": "spring-test",
  "nbf": 1699347283,
  "scope": [
    "openid",
    "profile",
    "email"
  ],
  "exp": 1699347583,
  "iat": 1699347283,
  "email": "test-user@d3softtech.com",
  "username": "d3user"
}
```

We can see that the JWT body contains additional claims like:

1. roles
2. isPasswordChangeRequired
3. userId
4. ssn
5. email
6. username

which we provided in Customizer for the token. Similarly, you can add as many claims as you want.

#### Introspection response using access_token

```json
{
  "active": true,
  "client_id": "spring-test",
  "iat": 1698757155,
  "exp": 1698760755
}
```

The default response for /oauth2/introspect will just return the status of access_token. And it can
be customized as well if required.

### Opaque Token:

#### Code flow - code-exchange response

```json
{
  "access_token": "vbHFMLGQPmqAWWOzjLoYNu_RG1jBHc7oifI9Hl9N1eCyG3jdzTgAoN8YXAAK-GfEy1CUhokTAnM2aC4GsDe07OgPBpI_sAGHP60pQgbTDTyBUJj2jO1inIi0FoCpmPcj",
  "refresh_token": "Rj8CpnQexjtFJzCPFJUmhKGVmgdFAJ6RLMB_h6SwYgDItPLwSu6AR7CZ3WpIEQthm7pGEpis7NlrarvIHX5YjwBX6wGwWpwfnIKVSa0OJYJqhFsZfFvOmn8sypi4DS4b",
  "scope": "openid profile email",
  "token_type": "Bearer",
  "expires_in": 299
}
```

At the end of the code flow, you will have the JSON response encapsulating `access_token`,
`refresh_token`, `scope`, `token_type` and `expires_in`.

To pull the claims of the authenticated user we have to invoke the `/oauth2/introspect` endpoint
against spring-oauth-server.

#### Introspection response using access_token without Customizer

```json
{
  "active": true,
  "sub": "d3user",
  "aud": [
    "spring-reference"
  ],
  "nbf": 1698755697,
  "scope": "openid profile email",
  "iss": "http://localhost:6060",
  "exp": 1698755997,
  "iat": 1698755697,
  "jti": "2b4165c0-68f3-4e3d-b67e-d50c3f7b6110",
  "client_id": "spring-reference",
  "token_type": "Bearer"
}
```

Without customizer, it has all default claims like status "active" and subject (sub), for the user
authenticated in code flow.

#### Introspection response using access_token with Customizer

```json
{
  "active": true,
  "sub": "d3user",
  "roles": [
    "admin",
    "user"
  ],
  "iss": "http://localhost:6060",
  "isPasswordChangeRequired": true,
  "userId": 123,
  "ssn": "197611119877",
  "aud": [
    "spring-reference"
  ],
  "nbf": 1698755588,
  "scope": "openid profile email",
  "exp": 1698755888,
  "iat": 1698755588,
  "operatorId": "197611119877",
  "jti": "c0560938-c413-44f7-a01b-9cbc119eae58",
  "email": "test-user@d3softtech.com",
  "username": "d3user",
  "client_id": "spring-reference",
  "token_type": "Bearer"
}
```

With customizer, the access_token will have additional claims like:

1. roles
2. isPasswordChangeRequired
3. userId
4. ssn
5. operatorId
6. email
7. username

<B>NOTE:</B> If you are using spring security in your service then introspection will be taken care
by security layer. I will cover the spring security with oauth2-resource-server in details in a
separate POC.