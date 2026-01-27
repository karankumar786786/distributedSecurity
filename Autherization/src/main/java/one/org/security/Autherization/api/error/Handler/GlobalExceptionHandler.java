package one.org.security.Autherization.api.error.Handler;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import one.org.security.Autherization.api.error.CustomError.ClientNotFoundException;
import one.org.security.Autherization.api.error.StandardErrorApiResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ClientNotFoundException.class)
    public ResponseEntity<StandardErrorApiResponse> handleClientNotFoundException(ClientNotFoundException ex) {
        return build(HttpStatus.NOT_FOUND, ex.getMessage(), null);
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<StandardErrorApiResponse> handleSecurityException(SecurityException ex) {
        return build(HttpStatus.FORBIDDEN, ex.getMessage(), null);
    }

    @ExceptionHandler(DuplicateKeyException.class)
    public ResponseEntity<StandardErrorApiResponse> handleDuplicateKeyException(DuplicateKeyException ex) {
        return build(HttpStatus.CONFLICT, ex.getMessage(), null);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<StandardErrorApiResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        List<String> details = ex.getBindingResult()
                .getAllErrors()
                .stream()
                .map(error -> error.getDefaultMessage())
                .collect(java.util.stream.Collectors.toList());
        return build(HttpStatus.BAD_REQUEST, "Validation Error", details);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<StandardErrorApiResponse> handleGenericException(Exception ex) {
        ex.printStackTrace(); // Log the error ideally
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred", List.of(ex.getMessage()));
    }

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
