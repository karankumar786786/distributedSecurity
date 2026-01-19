package one.org.security.ProcessedSmsConsumer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "one.org.security")
public class ProcessedSmsConsumerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProcessedSmsConsumerApplication.class, args);
	}

}
