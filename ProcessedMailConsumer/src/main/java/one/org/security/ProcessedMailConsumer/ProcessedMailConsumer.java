package one.org.security.ProcessedMailConsumer;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import one.org.security.avro.ProcessedMail;

@Service
@Slf4j
public class ProcessedMailConsumer {

    @KafkaListener(topics = "${spring.kafkaConfig.topics.processed-mail}", groupId = "${spring.kafkaConfig.consumer.group-id}")
    public void consumeAndLog(ConsumerRecord<String, ProcessedMail> record) {
        ProcessedMail batch = record.value();

        if (batch == null || batch.getMails() == null || batch.getMails().isEmpty()) {
            return;
        }

        log.info("Processed Mail Batch - Key: {}, Count: {}", record.key(), batch.getMails().size());
        batch.getMails().forEach(mail -> log.info("Mail To: {}, Subject: {}, Body: {}", mail.getTo(), mail.getSubject(),
                mail.getBody()));
    }
}
