package one.org.security.ProcessedSmsConsumer.sms.consumer;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import one.org.security.avro.ProcessedSms;

@Service
@Slf4j
public class ProcessedSmsConsumer {

    @KafkaListener(topics = "${spring.kafkaConfig.topics.processed-sms}", groupId = "${spring.kafkaConfig.consumer.group-id}")
    public void consumeAndLog(ConsumerRecord<String, ProcessedSms> record) {
        ProcessedSms batch = record.value();

        if (batch == null || batch.getSmsList() == null || batch.getSmsList().isEmpty()) {
            return;
        }

        log.info("Processed SMS Batch - Key: {}, Count: {}", record.key(), batch.getSmsList().size());
        batch.getSmsList().forEach(sms -> log.info("SMS To: {}, Message: {}", sms.getTo(), sms.getMessage()));
    }
}
