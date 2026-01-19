package one.org.security.SecurityEventStreamProcessor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.kafka.annotation.EnableKafkaStreams;

@SpringBootApplication
@ComponentScan(basePackages = "one.org.security")
@EnableKafkaStreams
public class SecurityEventStreamProcessorApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityEventStreamProcessorApplication.class, args);
	}

}
