package one.org.security.sms.stream;

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
import one.org.security.avro.ProcessedSms;
import one.org.security.avro.Sms;

@Service
@Slf4j
@RequiredArgsConstructor
public class SmsProcessingStream {

    @Value("${spring.kafkaConfig.schema.registry.url}")
    private String schemaRegistryUrl;

    @Value("${spring.kafkaConfig.topics.sms}")
    private String smsTopicName;

    @Value("${spring.kafkaConfig.topics.processed-sms}")
    private String processedSmsTopicName;

    @Value("${spring.kafkaConfig.window.duration-ms:10000}")
    private long windowDurationMs;

    private Map<String, String> config() {
        return Collections.singletonMap("schema.registry.url", schemaRegistryUrl);
    }

    @Autowired
    public void processSms(StreamsBuilder streamBuilder) {
        Map<String, String> serdeConfig = config();

        SpecificAvroSerde<Sms> smsSerde = new SpecificAvroSerde<>();
        smsSerde.configure(serdeConfig, false);

        SpecificAvroSerde<ProcessedSms> processedSmsSerde = new SpecificAvroSerde<>();
        processedSmsSerde.configure(serdeConfig, false);

        KStream<String, Sms> smsStream = streamBuilder.stream(
                smsTopicName,
                Consumed.with(Serdes.String(), smsSerde));

        smsStream.groupByKey()
                .windowedBy(TimeWindows.ofSizeWithNoGrace(Duration.ofMillis(windowDurationMs)))
                .aggregate(
                        () -> ProcessedSms.newBuilder().setSmsList(new ArrayList<>()).build(),
                        (key, value, aggregate) -> {
                            List<Sms> list = new ArrayList<>(aggregate.getSmsList());
                            list.add(value);
                            return ProcessedSms.newBuilder().setSmsList(list).build();
                        },
                        Materialized.with(Serdes.String(), processedSmsSerde))
                .toStream()
                .map((windowedKey, value) -> new KeyValue<>(windowedKey.key(), value))
                .to(processedSmsTopicName, Produced.with(Serdes.String(), processedSmsSerde));
    }
}
