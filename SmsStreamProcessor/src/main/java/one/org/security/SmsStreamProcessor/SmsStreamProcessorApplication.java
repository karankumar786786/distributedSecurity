package one.org.security.SmsStreamProcessor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.kafka.annotation.EnableKafkaStreams;

@SpringBootApplication
@ComponentScan(basePackages = "one.org.security")
@EnableKafkaStreams
public class SmsStreamProcessorApplication {

	public static void main(String[] args) {
		SpringApplication.run(SmsStreamProcessorApplication.class, args);
	}

}
