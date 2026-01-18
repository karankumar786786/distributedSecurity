package one.org.security.infrastructure.security.filter;

import org.springframework.stereotype.Service;
import net.devh.boot.grpc.client.inject.GrpcClient;
import one.org.security.passwordEncoding.EncodeRequest;
import one.org.security.passwordEncoding.EncodeResponse;
import one.org.security.passwordEncoding.PasswordEncodingServiceGrpc.PasswordEncodingServiceBlockingStub;
import one.org.security.passwordEncoding.VerifyRequest;
import one.org.security.passwordEncoding.VerifyResponse;

@Service
public class EncodingService {

    @GrpcClient("password-encoding-service")
    private PasswordEncodingServiceBlockingStub blockingStub;

    public String encode(String password) {
        EncodeRequest request = EncodeRequest.newBuilder()
                .setPassword(password)
                .build();
        EncodeResponse response = blockingStub.encode(request);
        return response.getEncodedPassword();
    }

    public boolean verify(String password, String encodedPassword) {
        VerifyRequest request = VerifyRequest.newBuilder()
                .setPassword(password)
                .setEncodedPassword(encodedPassword)
                .build();
        VerifyResponse response = blockingStub.verify(request);
        System.out.println(response.getResult());
        return response.getResult();
    }
}
