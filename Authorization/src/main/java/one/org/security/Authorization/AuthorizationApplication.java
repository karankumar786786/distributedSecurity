package one.org.security.Authorization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

@SpringBootApplication
@EnableMongoRepositories(basePackages = "one.org.security.Authorization.core.repository")
@org.springframework.context.annotation.ComponentScan(basePackages = { "one.org.security.Authorization",
		"one.org.security.common" })
public class AuthorizationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationApplication.class, args);
	}

}
