package org.d3softtech.oauth2.server.token.customizer;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

import java.util.Map;
import org.d3softtech.oauth2.server.userdetails.D3UserDetails;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;


@Component
public class OAuth2OpaqueTokenIntrospectionResponseCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {

  @Override
  public void customize(OAuth2TokenClaimsContext jwtContext) {
    if (AUTHORIZATION_CODE.equals(jwtContext.getAuthorizationGrantType()) && ACCESS_TOKEN.equals(
        jwtContext.getTokenType())) {
      UsernamePasswordAuthenticationToken authenticatedUserToken = jwtContext.getPrincipal();
      D3UserDetails userDetails = (D3UserDetails) authenticatedUserToken.getPrincipal();
      Map.of("userId", userDetails.getUserId(),
              "username", userDetails.getUsername(),
              "isPasswordChangeRequired", userDetails.isPasswordChangeRequired(),
              "roles", userDetails.getRoles(),
              "ssn", userDetails.getSsn(),
              "email", userDetails.getEmail(),
              "operatorId", userDetails.getSsn())
          .forEach((key, value) -> jwtContext.getClaims().claim(key, value));
    }
  }
}
