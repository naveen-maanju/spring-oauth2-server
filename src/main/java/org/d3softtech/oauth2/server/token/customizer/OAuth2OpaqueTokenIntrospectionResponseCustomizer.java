package org.d3softtech.oauth2.server.token.customizer;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

import java.util.Map;
import java.util.function.Consumer;
import org.d3softtech.oauth2.server.userdetails.D3UserDetails;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;


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
