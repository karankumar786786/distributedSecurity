package one.org.security.ProcessedSecurityEventConsumer.event.consumer.entity;

import java.time.Instant;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import com.mongodb.lang.NonNull;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import one.org.security.common.enums.Event;

@Document(collection = "security_event")
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class SecurityEvent {
    @Id
    private ObjectId id;
    @NonNull
    @Indexed
    private ObjectId user;
    @NotNull
    private String deviceHashKeyId;
    @NonNull
    private String deviceHash;
    @NonNull
    private String ipAddress;
    @NonNull
    private Event event;
    private String message;
    @NonNull
    @Builder.Default
    private Instant createdAt = Instant.now();

}
