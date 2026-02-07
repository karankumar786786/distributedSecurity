package one.org.security.Autherization.api.error.Handler;

import java.nio.file.AccessDeniedException;
import java.time.LocalDateTime;
import java.util.List;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import lombok.extern.slf4j.Slf4j;
import one.org.security.Autherization.api.error.CustomError.AuthorizationNotFoundException;
import one.org.security.Autherization.api.error.CustomError.ClientNotFoundException;
import one.org.security.Autherization.api.error.StandardErrorApiResponse;

@Slf4j
@RestControllerAdvice(basePackages = "one.org.security.Autherization.api")
public class GlobalExceptionHandler {

    @ExceptionHandler(ClientNotFoundException.class)
    public ResponseEntity<StandardErrorApiResponse> handleClientNotFoundException(ClientNotFoundException ex) {
        log.warn("Client not found: {}", ex.getMessage());
        return build(HttpStatus.NOT_FOUND, ex.getMessage(), null);
    }

    @ExceptionHandler(AuthorizationNotFoundException.class)
    public ResponseEntity<StandardErrorApiResponse> handleAuthorizationNotFoundException(
            AuthorizationNotFoundException ex) {
        log.warn("Authorization not found: {}", ex.getMessage());
        return build(HttpStatus.NOT_FOUND, ex.getMessage(), null);
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<StandardErrorApiResponse> handleSecurityException(SecurityException ex) {
        log.warn("Security exception: {}", ex.getMessage());
        return build(HttpStatus.FORBIDDEN, ex.getMessage(), null);
    }

    @ExceptionHandler(DuplicateKeyException.class)
    public ResponseEntity<StandardErrorApiResponse> handleDuplicateKeyException(DuplicateKeyException ex) {
        log.warn("Duplicate key: {}", ex.getMessage());
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
        log.debug("Validation error: {}", details);
        return build(HttpStatus.BAD_REQUEST, "Validation Error", details);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<StandardErrorApiResponse> handleHttpRequestMethodNotSupportedException(
            HttpRequestMethodNotSupportedException ex) {
        return build(HttpStatus.METHOD_NOT_ALLOWED, ex.getMessage(), null);
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<StandardErrorApiResponse> handleHttpMediaTypeNotSupportedException(
            HttpMediaTypeNotSupportedException ex) {
        return build(HttpStatus.UNSUPPORTED_MEDIA_TYPE, ex.getMessage(), null);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<StandardErrorApiResponse> handleHttpMessageNotReadableException(
            HttpMessageNotReadableException ex) {
        log.warn("Malformed JSON request: {}", ex.getMessage());
        return build(HttpStatus.BAD_REQUEST, "Malformed JSON request", List.of(ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<StandardErrorApiResponse> handleMethodArgumentTypeMismatchException(
            MethodArgumentTypeMismatchException ex) {
        return build(HttpStatus.BAD_REQUEST,
                String.format("The parameter '%s' of value '%s' could not be converted to type '%s'", ex.getName(),
                        ex.getValue(), ex.getRequiredType().getSimpleName()),
                null);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<StandardErrorApiResponse> handleMissingServletRequestParameterException(
            MissingServletRequestParameterException ex) {
        return build(HttpStatus.BAD_REQUEST, ex.getMessage(), null);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<StandardErrorApiResponse> handleAccessDeniedException(
            AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());
        return build(HttpStatus.FORBIDDEN, "Access Denied", List.of("Access denied"));
    }

    @ExceptionHandler(NoSuchMethodError.class)
    public ResponseEntity<StandardErrorApiResponse> handleNoSuchMethodError(NoSuchMethodError ex) {
        log.error("Method Not Found Error: {}", ex.getMessage(), ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred", null);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<StandardErrorApiResponse> handleGenericException(Exception ex) {
        log.error("Unexpected error: {}", ex.getMessage(), ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred", null);
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
