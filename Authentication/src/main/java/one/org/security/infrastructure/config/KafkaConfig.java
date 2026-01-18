package one.org.security.infrastructure.config;

import io.confluent.kafka.serializers.KafkaAvroDeserializer;
import io.confluent.kafka.serializers.KafkaAvroDeserializerConfig;
import io.confluent.kafka.serializers.KafkaAvroSerializer;
import io.confluent.kafka.streams.serdes.avro.SpecificAvroSerde;

import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.StreamsConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafkaStreams;
import org.springframework.kafka.annotation.KafkaStreamsDefaultConfiguration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.config.KafkaStreamsConfiguration;
import org.springframework.kafka.core.*;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafkaConfig.server.address}")
    private String bootstrapServers;

    @Value("${spring.kafkaConfig.consumer.group-id}")
    private String groupId;

    @Value("${spring.kafkaConfig.schema.registry.url}")
    private String schemaRegistryUrl;

    @Value("${spring.kafkaConfig.topics.mail}")
    private String mailTopicName;

    @Value("${spring.kafkaConfig.topics.sms}")
    private String smsTopicName;

    @Value("${spring.kafkaConfig.topics.processed-mail}")
    private String processedMailTopicName;

    @Value("${spring.kafkaConfig.topics.processed-sms}")
    private String processedSmsTopicName;

    @Value("${spring.kafkaConfig.topics.security-event}")
    private String securityEventTopicName;

    @Value("${spring.kafkaConfig.topics.processed-security-event}")
    private String processedSecurityEventTopicName;

    @Bean
    public KafkaAdmin kafkaAdmin() {
        Map<String, Object> config = new HashMap<>();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        return new KafkaAdmin(config);
    }

    // --- Topics ---
    @Bean
    public NewTopic mailTopic() {
        return new NewTopic(mailTopicName, 3, (short) 1);
    }

    @Bean
    public NewTopic smsTopic() {
        return new NewTopic(smsTopicName, 3, (short) 1);
    }

    @Bean
    public NewTopic processedMailTopic() {
        return new NewTopic(processedMailTopicName, 3, (short) 1);
    }

    @Bean
    public NewTopic processedSmsTopic() {
        return new NewTopic(processedSmsTopicName, 3, (short) 1);
    }

    @Bean
    public NewTopic securityEventTopic() {
        return new NewTopic(securityEventTopicName, 3, (short) 1);
    }

    @Bean
    public NewTopic processedSecurityEventTopic() {
        return new NewTopic(processedSecurityEventTopicName, 3, (short) 1);
    }

    private Map<String, Object> commonConfig() {
        Map<String, Object> props = new HashMap<>();
        props.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put("schema.registry.url", schemaRegistryUrl);
        return props;
    }

    @Bean
    public ProducerFactory<String, Object> multiProducerFactory() {
        Map<String, Object> configProps = commonConfig();
        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaAvroSerializer.class);
        return new DefaultKafkaProducerFactory<>(configProps);
    }

    /**
     * One Template to rule them all.
     * Because it uses 'Object', you can pass Mail, Sms, or ProcessedMail into it.
     */
    @Bean(name = "avroKafkaTemplate")
    public KafkaTemplate<String, Object> kafkaTemplate() {
        return new KafkaTemplate<>(multiProducerFactory());
    }

    @Bean
    public ConsumerFactory<String, Object> multiConsumerFactory() {
        Map<String, Object> configProps = commonConfig();
        configProps.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        configProps.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        configProps.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, KafkaAvroDeserializer.class);
        configProps.put(KafkaAvroDeserializerConfig.SPECIFIC_AVRO_READER_CONFIG, true);
        return new DefaultKafkaConsumerFactory<>(configProps);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(multiConsumerFactory());
        return factory;
    }
}