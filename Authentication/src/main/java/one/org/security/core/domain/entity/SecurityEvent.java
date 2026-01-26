package one.org.security.core.domain.entity;

import java.time.Instant;

import org.bson.types.ObjectId;

import com.mongodb.lang.NonNull;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import one.org.security.core.domain.dto.Event;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class SecurityEvent {

    private ObjectId id;
    @NonNull
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
