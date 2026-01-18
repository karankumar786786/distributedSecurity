package one.org.security.ConsumerService;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.bson.types.ObjectId;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import one.org.security.avro.ProcessedSecurityEventLog;
import one.org.security.avro.SecurityEventLog;
import one.org.security.core.domain.entity.SecurityEvent;
import one.org.security.core.domain.enums.Event;
import one.org.security.infrastructure.persistence.SecurityEventRepository;

@Service
@Slf4j
@RequiredArgsConstructor
public class ProcessedSecurityEventConsumer {

    private final SecurityEventRepository securityEventRepository;

    @KafkaListener(topics = "${spring.kafkaConfig.topics.processed-security-event}", groupId = "${spring.kafkaConfig.consumer.group-id}")
    public void consumeAndSave(ConsumerRecord<String, ProcessedSecurityEventLog> record) {
        ProcessedSecurityEventLog batch = record.value();

        if (batch == null || batch.getSecurityEvents() == null || batch.getSecurityEvents().isEmpty()) {
            return;
        }

        log.info("Persisting window batch: {} events for key {}", batch.getSecurityEvents().size(), record.key());

        List<SecurityEvent> entities = batch.getSecurityEvents().stream()
                .map(this::mapToEntity)
                .collect(Collectors.toList());

        securityEventRepository.saveAll(entities);
    }

    private SecurityEvent mapToEntity(SecurityEventLog avro) {
        return SecurityEvent.builder()
                .id(avro.getId() != null ? new ObjectId(String.valueOf(avro.getId())) : new ObjectId())
                .user(new ObjectId(String.valueOf(avro.getUser())))
                .deviceHash(String.valueOf(avro.getDeviceHash()))
                .ipAddress(String.valueOf(avro.getIpAddress()))
                .event(Event.valueOf(String.valueOf(avro.getEvent())))
                .message(avro.getMessage() != null ? String.valueOf(avro.getMessage()) : null)
                .createdAt(avro.getCreatedAt())
                .build();
    }
}
