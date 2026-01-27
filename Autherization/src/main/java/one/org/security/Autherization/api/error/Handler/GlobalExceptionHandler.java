package one.org.security.Autherization.api.error.Handler;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import one.org.security.Autherization.api.error.StandardErrorApiResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {


    




    private ResponseEntity<StandardErrorApiResponse> build(
            HttpStatus status,
            String message,
            List<String> details) {
        if (status == null) {
            throw new IllegalStateException("status is required");
        }

        if (details == null)
            details = List.of();
        return new ResponseEntity<>(
                StandardErrorApiResponse.builder()
                        .status(status.value())
                        .message(message)
                        .details(details)
                        .timeStamp(LocalDateTime.now())
                        .traceId(org.slf4j.MDC.get("traceId"))
                        .build(),
                status);
    }
}
