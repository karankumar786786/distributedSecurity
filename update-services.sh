#!/bin/bash

# Script to update all remaining microservices with observability configuration
# This script will be used as a reference for manual updates

SERVICES=(
    "ResourceServer"
    "passwordEncoding"
    "MailStreamProcessor"
    "SecurityEventStreamProcessor"
    "SmsStreamProcessor"
    "ProcessedMailConsumer"
    "ProcessedSecurityEventConsumer"
    "ProcessedSmsConsumer"
)

PORTS=(
    10002  # ResourceServer
    9000   # passwordEncoding (already set)
    10003  # MailStreamProcessor
    10004  # SecurityEventStreamProcessor
    10005  # SmsStreamProcessor
    10006  # ProcessedMailConsumer
    10007  # ProcessedSecurityEventConsumer
    10008  # ProcessedSmsConsumer
)

echo "Observability Integration - Remaining Services"
echo "=============================================="
echo ""
echo "Services to update:"
for i in "${!SERVICES[@]}"; do
    echo "$((i+1)). ${SERVICES[$i]} - Port: ${PORTS[$i]}"
done

echo ""
echo "For each service, the following changes are needed:"
echo "1. Update pom.xml: Spring Boot 4.0.2 + observability dependencies"
echo "2. Update application.yaml: Add otel, management, logging config"
echo "3. Add logback-spring.xml for Loki integration"
echo "4. Set unique port for Prometheus scraping"
