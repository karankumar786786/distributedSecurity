package one.org.security.passwordEncoding.Config;

import io.grpc.Status;
import org.springframework.grpc.server.exception.GrpcExceptionHandler;
import org.springframework.stereotype.Component;

@Component

public class GlobalGrpcExceptionHandler implements GrpcExceptionHandler {

    @Override
    public io.grpc.StatusException handleException(Throwable t) {
        if (t instanceof IllegalArgumentException) {
            System.out.println(t.getMessage());
            return Status.INVALID_ARGUMENT.withDescription(t.getMessage()).withCause(t).asException();
        }
        return Status.INTERNAL.withDescription(t.getMessage()).withCause(t).asException();
    }
}
