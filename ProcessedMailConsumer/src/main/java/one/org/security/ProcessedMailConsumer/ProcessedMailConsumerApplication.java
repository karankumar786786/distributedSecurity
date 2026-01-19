package one.org.security.ProcessedMailConsumer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "one.org.security")
public class ProcessedMailConsumerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProcessedMailConsumerApplication.class, args);
	}

}
