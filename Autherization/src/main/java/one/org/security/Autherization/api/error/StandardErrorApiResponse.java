package one.org.security.Autherization.api.error;

import java.time.LocalDateTime;
import java.util.List;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class StandardErrorApiResponse {
    private int status;
    private String message;
    private List<String> details;
    private LocalDateTime timeStamp;
    private String traceId;
}
