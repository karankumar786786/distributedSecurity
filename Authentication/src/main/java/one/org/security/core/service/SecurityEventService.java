package one.org.security.core.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import one.org.security.avro.SecurityEventLog;
import one.org.security.core.domain.entity.SecurityEvent;

@Service
public class SecurityEventService {
    @Autowired
    private KafkaTemplate<String, Object> kafkaTemplate;

    @Value("${spring.kafkaConfig.topics.security-event}")
    private String topicName;

    public boolean saveSecurityEvent(SecurityEvent securityEvent) {
        if (securityEvent == null) {
            throw new IllegalArgumentException("security event is null");
        }

        SecurityEventLog eventLog = SecurityEventLog.newBuilder()
                .setId(securityEvent.getId() != null ? securityEvent.getId().toHexString() : null)
                .setUser(securityEvent.getUser().toHexString())
                .setDeviceHash(securityEvent.getDeviceHash())
                .setIpAddress(securityEvent.getIpAddress())
                .setEvent(securityEvent.getEvent().name())
                .setMessage(securityEvent.getMessage())
                .setCreatedAt(securityEvent.getCreatedAt())
                .build();

        kafkaTemplate.send(topicName, eventLog.getUser().toString(), eventLog);
        return true;
    }
}
