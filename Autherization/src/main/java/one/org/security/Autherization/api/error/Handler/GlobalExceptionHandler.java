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
        return build(HttpStatus.FORBIDDEN, "Access Denied", List.of(ex.getMessage()));
    }

    @ExceptionHandler(NoSuchMethodError.class)
    public ResponseEntity<StandardErrorApiResponse> handleNoSuchMethodError(NoSuchMethodError ex) {
        ex.printStackTrace();
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Method Not Found Error: " + ex.getMessage(),
                List.of(ex.toString()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<StandardErrorApiResponse> handleGenericException(Exception ex) {
        // ex.printStackTrace(); // Log the error ideally
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
