package one.org.security.passwordEncoding.Services;

import io.grpc.stub.StreamObserver;
import one.org.security.passwordEncoding.EncodeRequest;
import one.org.security.passwordEncoding.EncodeResponse;
import one.org.security.passwordEncoding.PasswordEncodingServiceGrpc;
import one.org.security.passwordEncoding.VerifyRequest;
import one.org.security.passwordEncoding.VerifyResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.crypto.password.PasswordEncoder;

@GrpcService
public class PasswordEncodingService extends PasswordEncodingServiceGrpc.PasswordEncodingServiceImplBase {

    @Autowired
    private PasswordEncoder passwordEncoder;

    
    @Override
    public void encode(EncodeRequest request, StreamObserver<EncodeResponse> responseObserver) {
        String encodedPassword = passwordEncoder.encode(request.getPassword());
        EncodeResponse response = EncodeResponse.newBuilder()
                .setEncodedPassword(encodedPassword)
                .build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void verify(VerifyRequest request, StreamObserver<VerifyResponse> responseObserver) {
        boolean matches = passwordEncoder.matches(request.getPassword(), request.getEncodedPassword());
        VerifyResponse response = VerifyResponse.newBuilder()
                .setResult(matches)
                .build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }
}
