package org.d3softtech.oauth2.server.token.customizer;

import java.util.List;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

public class OAuth2JWTTokenCustomizerDelegate implements OAuth2TokenCustomizer<JwtEncodingContext> {

  private final List<OAuth2TokenCustomizer<JwtEncodingContext>> oAuth2TokenCustomizers;

  public OAuth2JWTTokenCustomizerDelegate() {
    oAuth2TokenCustomizers = List.of(
        new OAuth2AuthorizationCodeJWTTokenCustomizer(),
        new OAuth2ClientCredentialsJWTTokenCustomizer());
  }

  @Override
  public void customize(JwtEncodingContext context) {
    oAuth2TokenCustomizers.forEach(tokenCustomizer -> tokenCustomizer.customize(context));
  }
}
