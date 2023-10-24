package org.d3softtech.oauth2.server.response;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public record AuthorizationFlowStepResponse<T>(HttpHeaders httpHeaders, T body, HttpStatus httpStatus) {

  public static <T> AuthorizationFlowStepResponse<T> from(ResponseEntity<T> exchangeResult) {
    assertNotNull(exchangeResult, "Response entity is null");
    return new AuthorizationFlowStepResponse<>(exchangeResult.getHeaders(), exchangeResult.getBody(),
        HttpStatus.resolve(exchangeResult.getStatusCode().value()));

  }

}
