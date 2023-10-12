package org.d3softtech.oauth2.server.jwt.customizer;

import java.util.Map;
import org.d3softtech.oauth2.server.userdetails.D3UserDetails;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

public class OAuth2AuthenticatedUserTokenCustomizer implements CustomOAuth2TokenCustomizer {

    @Override
    public void customize(JwtEncodingContext jwtContext) {
        UsernamePasswordAuthenticationToken authenticatedUserToken = jwtContext.getPrincipal();
        D3UserDetails userDetails = (D3UserDetails) authenticatedUserToken.getPrincipal();
        Map.of("userId", userDetails.getUserId(),
                "username", userDetails.getUsername(),
                "isPasswordChangeRequired", userDetails.isPasswordChangeRequired(),
                "roles", userDetails.getRoles(),
                "operatorId", userDetails.getOperatorId())
            .forEach((key, value) -> jwtContext.getClaims().claim(key, value));

    }

    @Override
    public boolean isTokenSupported(JwtEncodingContext jwtContext) {
        return jwtContext.getPrincipal() instanceof UsernamePasswordAuthenticationToken;
    }
}
