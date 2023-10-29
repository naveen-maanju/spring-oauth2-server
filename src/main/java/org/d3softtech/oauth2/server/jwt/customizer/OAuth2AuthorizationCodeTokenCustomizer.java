package org.d3softtech.oauth2.server.jwt.customizer;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

import java.util.Map;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

public class OAuth2AuthorizationCodeTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

  @Override
  public void customize(JwtEncodingContext jwtContext) {
    if (AUTHORIZATION_CODE.equals(jwtContext.getAuthorizationGrantType()) && ACCESS_TOKEN.equals(
        jwtContext.getTokenType())) {
      OAuth2AuthorizationCodeAuthenticationToken oAuth2AuthorizationCodeAuthenticationToken = jwtContext.getAuthorizationGrant();
      Map<String, Object> additionalParameters = oAuth2AuthorizationCodeAuthenticationToken.getAdditionalParameters();
      additionalParameters.forEach((key, value) -> jwtContext.getClaims().claim(key, value));
    }
  }
}
