package org.d3softtech.oauth2.server.response;

import com.fasterxml.jackson.annotation.JsonProperty;

public record Token(@JsonProperty("access_token") String accessToken,
                    @JsonProperty("token_type") String tokenType,
                    @JsonProperty("expires_in") Integer expiresIn) {

}
