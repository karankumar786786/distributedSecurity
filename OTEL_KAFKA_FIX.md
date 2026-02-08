# OpenTelemetry Spring Boot 4.0.2 Compatibility Fix

## Issue

When integrating OpenTelemetry with Spring Boot 4.0.2, services failed to start with the following error:

```
java.lang.ClassNotFoundException: org.springframework.boot.autoconfigure.kafka.DefaultKafkaProducerFactoryCustomizer
```

### Root Cause

OpenTelemetry Spring Boot Starter (version 1.33.0-alpha) includes Kafka instrumentation autoconfiguration that is incompatible with Spring Boot 4.0.2. The autoconfiguration class attempts to load Kafka-related classes that have been moved or refactored in Spring Boot 4.x.

## Solution

Disable the OpenTelemetry Kafka instrumentation autoconfiguration by adding an exclusion in `application.yaml`:

```yaml
spring:
  autoconfigure:
    exclude:
      - io.opentelemetry.instrumentation.spring.autoconfigure.instrumentation.kafka.KafkaInstrumentationAutoConfiguration
```

## Services Updated

| Service        | File Updated                                         | Status                   |
| -------------- | ---------------------------------------------------- | ------------------------ |
| Authentication | `Authentication/src/main/resources/application.yaml` | ✅ Running on port 10000 |
| Authorization  | `Autherization/src/main/resources/application.yaml`  | ✅ Running on port 12000 |
| ResourceServer | `ResourceServer/src/main/resources/application.yaml` | ✅ Configuration updated |

## Impact

- **Tracing**: ✅ Still works (HTTP, gRPC, JDBC instrumentation remain active)
- **Metrics**: ✅ Still works (Prometheus metrics via Micrometer)
- **Logging**: ✅ Still works (Loki appender with trace context)
- **Kafka Tracing**: ⚠️ Disabled (Kafka instrumentation excluded)

## Alternative Solutions Attempted

1. **Dependency Exclusions** - Did not work because autoconfiguration class still loads
2. **Version Downgrade** - Not viable; need Spring Boot 4.0.2 for other features

## Recommendation

For services that use Kafka and require Kafka tracing:

- Consider using manual Kafka instrumentation
- Or wait for OpenTelemetry Spring Boot Starter to release a version compatible with Spring Boot 4.x
- Or use Spring Boot 3.3.x (Authorization server uses this due to OAuth2 Authorization Server compatibility)

## Verification

Services start successfully with:

- OpenTelemetry tracing enabled (Zipkin export)
- Prometheus metrics exposed at `/actuator/prometheus`
- Loki logging with trace context
- All non-Kafka instrumentation working

## Files Modified

1. `/Users/rahulgupta/Desktop/distributedSecurity/Authentication/src/main/resources/application.yaml`
2. `/Users/rahulgupta/Desktop/distributedSecurity/Autherization/src/main/resources/application.yaml`
3. `/Users/rahulgupta/Desktop/distributedSecurity/ResourceServer/src/main/resources/application.yaml`
4. `/Users/rahulgupta/Desktop/distributedSecurity/Authentication/pom.xml` (attempted exclusions - can be removed)
