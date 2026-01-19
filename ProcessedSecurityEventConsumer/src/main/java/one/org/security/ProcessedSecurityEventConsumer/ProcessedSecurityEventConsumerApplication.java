package one.org.security.ProcessedSecurityEventConsumer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "one.org.security")
public class ProcessedSecurityEventConsumerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProcessedSecurityEventConsumerApplication.class, args);
	}

}
