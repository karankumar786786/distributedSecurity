package one.org.security.passwordEncoding.Config;

import io.grpc.Status;
import org.springframework.grpc.server.exception.GrpcExceptionHandler;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class GlobalGrpcExceptionHandler implements GrpcExceptionHandler {

    @Override
    public io.grpc.StatusException handleException(Throwable t) {
        if (t instanceof IllegalArgumentException) {
            log.error("Argument error: {}", t.getMessage());
            return Status.INVALID_ARGUMENT.withDescription(t.getMessage()).withCause(t).asException();
        }
        return Status.INTERNAL.withDescription(t.getMessage()).withCause(t).asException();
    }
}
