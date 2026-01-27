package one.org.security.Autherization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = { "one.org.security.Autherization", "one.org.security.common" })
public class AutherizationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AutherizationApplication.class, args);
	}

}
