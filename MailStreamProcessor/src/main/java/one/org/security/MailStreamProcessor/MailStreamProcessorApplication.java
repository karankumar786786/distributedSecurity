package one.org.security.MailStreamProcessor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.kafka.annotation.EnableKafkaStreams;

@SpringBootApplication
@ComponentScan(basePackages = "one.org.security")
@EnableKafkaStreams
public class MailStreamProcessorApplication {

	public static void main(String[] args) {
		SpringApplication.run(MailStreamProcessorApplication.class, args);
	}

}
