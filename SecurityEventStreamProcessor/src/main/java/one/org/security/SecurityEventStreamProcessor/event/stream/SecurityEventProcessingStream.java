package one.org.security.SecurityEventStreamProcessor.event.stream;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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
import one.org.security.avro.ProcessedSecurityEventLog;
import one.org.security.avro.SecurityEventLog;

@Service
@Slf4j
@RequiredArgsConstructor
public class SecurityEventProcessingStream {

        @Value("${spring.kafkaConfig.schema.registry.url}")
        private String schemaRegistryUrl;

        @Value("${spring.kafkaConfig.topics.security-event}")
        private String securityEventTopic;

        @Value("${spring.kafkaConfig.topics.processed-security-event}")
        private String processedSecurityEventTopic;

        @Value("${spring.kafkaConfig.window.duration-ms:10000}")
        private long windowDurationMs;

        private Map<String, String> config() {
                return Collections.singletonMap("schema.registry.url", schemaRegistryUrl);
        }

        @Autowired
        public void processSecurityLogs(StreamsBuilder streamsBuilder) {
                Map<String, String> serdeConfig = config();

                SpecificAvroSerde<SecurityEventLog> inputSerde = new SpecificAvroSerde<>();
                inputSerde.configure(serdeConfig, false);

                SpecificAvroSerde<ProcessedSecurityEventLog> outputSerde = new SpecificAvroSerde<>();
                outputSerde.configure(serdeConfig, false);

                KStream<String, SecurityEventLog> logStream = streamsBuilder.stream(
                                securityEventTopic,
                                Consumed.with(Serdes.String(), inputSerde))
                                .peek((key, value) -> log.info("Processing key: {}", key));

                logStream.groupByKey()
                                .windowedBy(TimeWindows.ofSizeWithNoGrace(Duration.ofMillis(windowDurationMs)))
                                .aggregate(
                                                () -> ProcessedSecurityEventLog.newBuilder()
                                                                .setId(UUID.randomUUID().toString())
                                                                .setProcessedAt(Instant.now())
                                                                .setSecurityEvents(new ArrayList<>())
                                                                .build(),
                                                (key, value, aggregate) -> {
                                                        List<SecurityEventLog> list = new ArrayList<>(
                                                                        aggregate.getSecurityEvents());
                                                        list.add(value);
                                                        return ProcessedSecurityEventLog.newBuilder(aggregate)
                                                                        .setSecurityEvents(list)
                                                                        .build();
                                                },
                                                Materialized.with(Serdes.String(), outputSerde))
                                .toStream()
                                .map((windowedKey, aggregate) -> {
                                        // Update metadata for the final window output
                                        ProcessedSecurityEventLog finalized = ProcessedSecurityEventLog
                                                        .newBuilder(aggregate)
                                                        .setId(UUID.randomUUID().toString()) // Generate unique ID for
                                                                                             // the batch
                                                        .setProcessedAt(Instant.now())
                                                        .build();
                                        return new KeyValue<>(windowedKey.key(), finalized);
                                })
                                .to(processedSecurityEventTopic, Produced.with(Serdes.String(), outputSerde));
        }
}
