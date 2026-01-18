package one.org.security.api.Errors.Response;

import java.time.LocalDateTime;
import java.util.List;

public class StandardErroApiResponse {
    private int status;
    private String message;
    private List<String> details;
    private LocalDateTime timeStamp;
    private String traceId;

    public StandardErroApiResponse() {
    }

    public StandardErroApiResponse(int status, String message, List<String> details, LocalDateTime timeStamp,
            String traceId) {
        this.status = status;
        this.message = message;
        this.details = details;
        this.timeStamp = timeStamp;
        this.traceId = traceId;
    }

    public static StandardErroApiResponseBuilder builder() {
        return new StandardErroApiResponseBuilder();
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public List<String> getDetails() {
        return details;
    }

    public void setDetails(List<String> details) {
        this.details = details;
    }

    public LocalDateTime getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(LocalDateTime timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getTraceId() {
        return traceId;
    }

    public void setTraceId(String traceId) {
        this.traceId = traceId;
    }

    public static class StandardErroApiResponseBuilder {
        private int status;
        private String message;
        private List<String> details;
        private LocalDateTime timeStamp;
        private String traceId;

        StandardErroApiResponseBuilder() {
        }

        public StandardErroApiResponseBuilder status(int status) {
            this.status = status;
            return this;
        }

        public StandardErroApiResponseBuilder message(String message) {
            this.message = message;
            return this;
        }

        public StandardErroApiResponseBuilder details(List<String> details) {
            this.details = details;
            return this;
        }

        public StandardErroApiResponseBuilder timeStamp(LocalDateTime timeStamp) {
            this.timeStamp = timeStamp;
            return this;
        }

        public StandardErroApiResponseBuilder traceId(String traceId) {
            this.traceId = traceId;
            return this;
        }

        public StandardErroApiResponse build() {
            return new StandardErroApiResponse(status, message, details, timeStamp, traceId);
        }

        public String toString() {
            return "StandardErroApiResponse.StandardErroApiResponseBuilder(status=" + this.status + ", message="
                    + this.message + ", details=" + this.details + ", timeStamp=" + this.timeStamp + ", traceId="
                    + this.traceId + ")";
        }
    }
}
