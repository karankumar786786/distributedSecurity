package one.org.security.infrastructure.config;

import java.util.Arrays;

import org.bson.types.Binary;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.mongodb.core.convert.MongoCustomConversions;

import com.yubico.webauthn.data.ByteArray;

@Configuration
public class MongoConfig {

    @Bean
    public MongoCustomConversions mongoCustomConversions() {
        return new MongoCustomConversions(Arrays.asList(
                new ByteArrayWriteConverter(),
                new ByteArrayReadConverter()));
    }

    static class ByteArrayWriteConverter implements Converter<ByteArray, Binary> {
        @Override
        public Binary convert(ByteArray source) {
            return new Binary(source.getBytes());
        }
    }

    static class ByteArrayReadConverter implements Converter<Binary, ByteArray> {
        @Override
        public ByteArray convert(Binary source) {
            return new ByteArray(source.getData());
        }
    }
}
