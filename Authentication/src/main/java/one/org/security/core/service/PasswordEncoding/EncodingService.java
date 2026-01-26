package one.org.security.core.service.PasswordEncoding;

import org.springframework.stereotype.Service;
import net.devh.boot.grpc.client.inject.GrpcClient;
import lombok.extern.slf4j.Slf4j;
import one.org.security.passwordEncoding.EncodeRequest;
import one.org.security.passwordEncoding.EncodeResponse;
import one.org.security.passwordEncoding.PasswordEncodingServiceGrpc.PasswordEncodingServiceBlockingStub;
import one.org.security.passwordEncoding.VerifyRequest;
import one.org.security.passwordEncoding.VerifyResponse;

@Slf4j
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
        log.debug("Verification result: {}", response.getResult());
        return response.getResult();
    }
}
