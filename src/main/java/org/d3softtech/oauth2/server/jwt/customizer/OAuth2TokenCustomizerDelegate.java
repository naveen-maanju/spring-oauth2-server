package org.d3softtech.oauth2.server.jwt.customizer;

import java.util.List;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

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
