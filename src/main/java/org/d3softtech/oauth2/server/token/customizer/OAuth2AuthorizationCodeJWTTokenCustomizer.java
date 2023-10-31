package org.d3softtech.oauth2.server.token.customizer;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.d3softtech.oauth2.server.userdetails.D3UserDetails;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Slf4j
public class OAuth2AuthorizationCodeJWTTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

  @Override
  public void customize(JwtEncodingContext jwtContext) {
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
      log.debug("Customized the token!");
    }
  }
}
