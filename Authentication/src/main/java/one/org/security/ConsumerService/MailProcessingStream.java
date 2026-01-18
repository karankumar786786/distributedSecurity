package one.org.security.ConsumerService;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.KeyValue;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.KStream;
import org.apache.kafka.streams.kstream.Materialized;
import org.apache.kafka.streams.kstream.Produced;
import org.apache.kafka.streams.kstream.TimeWindows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.confluent.kafka.streams.serdes.avro.SpecificAvroSerde;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import one.org.security.avro.Mail;
import one.org.security.avro.ProcessedMail;

@Service
@Slf4j
@RequiredArgsConstructor
public class MailProcessingStream {

    @Value("${spring.kafkaConfig.schema.registry.url}")
    private String schemaRegistryUrl;

    @Value("${spring.kafkaConfig.topics.mail}")
    private String mailTopicName;

    @Value("${spring.kafkaConfig.topics.processed-mail}")
    private String processedMailTopicName;

    @Value("${spring.kafkaConfig.window.duration-ms:10000}")
    private long windowDurationMs;

    private Map<String, String> config() {
        return Collections.singletonMap("schema.registry.url", schemaRegistryUrl);
    }

    @Autowired
    public void processMail(StreamsBuilder streamBuilder) {
        Map<String, String> serdeConfig = config();

        SpecificAvroSerde<Mail> mailSerde = new SpecificAvroSerde<>();
        mailSerde.configure(serdeConfig, false);

        SpecificAvroSerde<ProcessedMail> processedMailSerde = new SpecificAvroSerde<>();
        processedMailSerde.configure(serdeConfig, false);

        KStream<String, Mail> mailStream = streamBuilder.stream(
                mailTopicName,
                Consumed.with(Serdes.String(), mailSerde));

        mailStream.groupByKey()
                .windowedBy(TimeWindows.ofSizeWithNoGrace(Duration.ofMillis(windowDurationMs)))
                .aggregate(
                        () -> ProcessedMail.newBuilder().setMails(new ArrayList<>()).build(),
                        (key, value, aggregate) -> {
                            List<Mail> list = new ArrayList<>(aggregate.getMails());
                            list.add(value);
                            return ProcessedMail.newBuilder().setMails(list).build();
                        },
                        Materialized.with(Serdes.String(), processedMailSerde))
                .toStream()
                .map((windowedKey, value) -> new KeyValue<>(windowedKey.key(), value))
                .to(processedMailTopicName, Produced.with(Serdes.String(), processedMailSerde));
    }
}
