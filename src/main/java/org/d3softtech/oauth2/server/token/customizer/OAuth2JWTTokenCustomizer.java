package org.d3softtech.oauth2.server.token.customizer;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

import java.util.Map;
import java.util.function.Consumer;
import org.d3softtech.oauth2.server.userdetails.D3UserDetails;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

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
