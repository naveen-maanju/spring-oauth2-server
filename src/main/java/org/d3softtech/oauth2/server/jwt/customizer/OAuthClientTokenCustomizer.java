package org.d3softtech.oauth2.server.jwt.customizer;

import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

public class OAuthClientTokenCustomizer implements CustomOAuth2TokenCustomizer {

    @Override
    public void customize(JwtEncodingContext jwtContext) {
        OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = jwtContext.getAuthorizationGrant();
        clientCredentialsAuthentication.getAdditionalParameters()
            .forEach((key, value) -> jwtContext.getClaims().claim(key, value));
    }

    @Override
    public boolean isTokenSupported(JwtEncodingContext jwtContext) {
        return jwtContext.getPrincipal() instanceof OAuth2ClientAuthenticationToken;
    }
}
