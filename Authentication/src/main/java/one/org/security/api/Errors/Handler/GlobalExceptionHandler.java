package one.org.security.api.Errors.Handler;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import org.springframework.dao.DuplicateKeyException;

import jakarta.validation.ConstraintViolationException;
import one.org.security.api.Errors.CentralErrorMessageResponse;
import one.org.security.api.Errors.CustomExceptions.InvalidTokenException;
import one.org.security.api.Errors.CustomExceptions.MailNotSentException;
import one.org.security.api.Errors.CustomExceptions.ResourceNotFoundException;
import one.org.security.api.Errors.CustomExceptions.SmsNotSentException;
import one.org.security.api.Errors.CustomExceptions.UnauthorizedOperationException;
import one.org.security.api.Errors.CustomExceptions.UserAlreadyExistException;
import one.org.security.api.Errors.Response.StandardErroApiResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.web.bind.ServletRequestBindingException;

@RestControllerAdvice
public class GlobalExceptionHandler {
        private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(GlobalExceptionHandler.class);

        @ExceptionHandler(ResourceNotFoundException.class)
        public ResponseEntity<StandardErroApiResponse> handleResourseNotFound(
                        ResourceNotFoundException resourceNotFoundException) {
                return build(HttpStatus.NOT_FOUND, CentralErrorMessageResponse.RESOURCE_NOT_FOUND,
                                Collections.singletonList(resourceNotFoundException.getMessage()));
        }

        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<StandardErroApiResponse> handleIllegalArgument(
                        IllegalArgumentException illegalArgumentException) {
                log.error(illegalArgumentException.getMessage());
                return build(HttpStatus.BAD_REQUEST, CentralErrorMessageResponse.BAD_REQUEST,
                                Collections.singletonList(illegalArgumentException.getMessage()));
        }

        @ExceptionHandler(UserAlreadyExistException.class)
        public ResponseEntity<StandardErroApiResponse> handleUserAlreadyExist(
                        UserAlreadyExistException userAlreadyExistException) {
                return build(HttpStatus.CONFLICT, CentralErrorMessageResponse.USER_ALREADY_EXIST_ERROR,
                                Collections.singletonList(userAlreadyExistException.getMessage()));
        }

        @ExceptionHandler(MethodArgumentNotValidException.class)
        public ResponseEntity<StandardErroApiResponse> handleMethodArgumentNotValid(
                        MethodArgumentNotValidException ex) {
                List<String> errors = ex.getBindingResult()
                                .getFieldErrors()
                                .stream()
                                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                                .collect(Collectors.toList());

                return build(HttpStatus.BAD_REQUEST, CentralErrorMessageResponse.VALIDATION_FAILED, errors);
        }

        @ExceptionHandler(HttpMessageNotReadableException.class)
        public ResponseEntity<StandardErroApiResponse> handleMissingRequestBody(
                        HttpMessageNotReadableException ex) {
                return build(HttpStatus.BAD_REQUEST, CentralErrorMessageResponse.BAD_REQUEST,
                                Collections.singletonList(CentralErrorMessageResponse.INVALID_JSON_ERROR));
        }

        @ExceptionHandler(ConstraintViolationException.class)
        public ResponseEntity<StandardErroApiResponse> handleConstraintViolation(
                        ConstraintViolationException ex) {
                return build(HttpStatus.BAD_REQUEST, CentralErrorMessageResponse.BAD_REQUEST,
                                Collections.singletonList(ex.getMessage()));
        }

        @ExceptionHandler(AccessDeniedException.class)
        public ResponseEntity<StandardErroApiResponse> handleAccessDenied(
                        AccessDeniedException ex) {
                return build(HttpStatus.FORBIDDEN, CentralErrorMessageResponse.ACCESS_DENIED,
                                Collections.singletonList(CentralErrorMessageResponse.ACCESSS_DENIED_MESSAGE));
        }

        @ExceptionHandler(AuthenticationException.class)
        public ResponseEntity<StandardErroApiResponse> handleAuthentication(
                        AuthenticationException ex) {
                return build(HttpStatus.UNAUTHORIZED, CentralErrorMessageResponse.AUTH_FAILED,
                                Collections.singletonList(ex.getMessage()));
        }

        @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
        public ResponseEntity<StandardErroApiResponse> handleMethodNotSupported(
                        HttpRequestMethodNotSupportedException ex) {
                return build(HttpStatus.METHOD_NOT_ALLOWED, CentralErrorMessageResponse.METHOD_NOT_ALLOWED,
                                Collections.singletonList("Supported methods: " + ex.getSupportedHttpMethods()));
        }

        @ExceptionHandler(BadCredentialsException.class)
        public ResponseEntity<StandardErroApiResponse> handleBadCredential(BadCredentialsException ex) {
                return build(HttpStatus.UNAUTHORIZED, CentralErrorMessageResponse.UNAUTHORIZED,
                                Collections.singletonList(ex.getMessage()));
        }

        @ExceptionHandler(DuplicateKeyException.class)
        public ResponseEntity<StandardErroApiResponse> handleDuplicateKey(DuplicateKeyException ex) {
                return build(
                                HttpStatus.CONFLICT,
                                CentralErrorMessageResponse.USER_ALREADY_EXIST_ERROR,
                                List.of("user already exist with provided username"));
        }

        @ExceptionHandler(InvalidTokenException.class)
        public ResponseEntity<StandardErroApiResponse> handleInvalidToken(InvalidTokenException ex) {
                return build(HttpStatus.UNAUTHORIZED, CentralErrorMessageResponse.AUTH_FAILED,
                                Collections.singletonList(ex.getMessage()));
        }

        @ExceptionHandler(UnauthorizedOperationException.class)
        public ResponseEntity<StandardErroApiResponse> handleUnauthorizedOperation(UnauthorizedOperationException ex) {
                return build(HttpStatus.UNAUTHORIZED, CentralErrorMessageResponse.ACCESS_DENIED,
                                Collections.singletonList(ex.getMessage()));
        }

        @ExceptionHandler(NoResourceFoundException.class)
        public ResponseEntity<StandardErroApiResponse> handleNoResourceFoundException(NoResourceFoundException ex) {
                return build(HttpStatus.NOT_FOUND, CentralErrorMessageResponse.RESOURCE_NOT_FOUND,
                                Collections.singletonList(ex.getMessage()));
        }

        @ExceptionHandler(ServletRequestBindingException.class)
        public ResponseEntity<StandardErroApiResponse> handleServletRequestBindingException(
                        ServletRequestBindingException ex) {
                return build(HttpStatus.BAD_REQUEST, CentralErrorMessageResponse.BAD_REQUEST,
                                Collections.singletonList(ex.getMessage()));
        }

        @ExceptionHandler(MailNotSentException.class)
        public ResponseEntity<StandardErroApiResponse> handleMailNotSentException(MailNotSentException ex) {
                return build(HttpStatus.INTERNAL_SERVER_ERROR, CentralErrorMessageResponse.INTERNAL_ERROR,
                                Collections.singletonList(ex.getMessage()));
        }

        @ExceptionHandler(SmsNotSentException.class)
        public ResponseEntity<StandardErroApiResponse> handleSmsNotSentException(SmsNotSentException ex) {
                return build(HttpStatus.INTERNAL_SERVER_ERROR, CentralErrorMessageResponse.INTERNAL_ERROR,
                                Collections.singletonList(ex.getMessage()));
        }

        @ExceptionHandler(Exception.class)
        public ResponseEntity<StandardErroApiResponse> handleAllUnhandled(
                        Exception ex) {
                log.error("Unhandled exception", ex);
                return build(HttpStatus.INTERNAL_SERVER_ERROR, CentralErrorMessageResponse.INTERNAL_ERROR,
                                Collections.singletonList(CentralErrorMessageResponse.INTERNAL_ERROR_MESSAGE));
        }

        private ResponseEntity<StandardErroApiResponse> build(
                        HttpStatus status,
                        String message,
                        List<String> details) {
                if (status == null) {
                        throw new IllegalStateException("status is required");
                }
                ;
                if (details == null)
                        details = List.of();
                return new ResponseEntity<>(
                                StandardErroApiResponse.builder()
                                                .status(status.value())
                                                .message(message)
                                                .details(details)
                                                .timeStamp(LocalDateTime.now())
                                                .traceId(org.slf4j.MDC.get("traceId"))
                                                .build(),
                                status);
        }

}
