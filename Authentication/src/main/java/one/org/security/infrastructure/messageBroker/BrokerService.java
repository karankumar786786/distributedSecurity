package one.org.security.infrastructure.messageBroker;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;

import one.org.security.avro.Mail;
import one.org.security.avro.Sms;
import one.org.security.core.domain.dto.MailDTO;
import one.org.security.core.domain.dto.SmsDTO;

import org.springframework.stereotype.Service;

@Service
public class BrokerService {
    @Autowired
    @org.springframework.beans.factory.annotation.Qualifier("avroKafkaTemplate")
    private KafkaTemplate<String, Object> kafkaTemplate;

    @Value("${spring.kafkaConfig.topics.mail}")
    private String mailTopicName;

    @Value("${spring.kafkaConfig.topics.sms}")
    private String smsTopicName;

    public boolean sendOtpByMail(MailDTO mailDTO) {
        Mail mail = Mail.newBuilder().setTo(mailDTO.to()).setSubject(mailDTO.subject()).setBody(mailDTO.body()).build();
        kafkaTemplate.send(mailTopicName, mail.getTo().toString(), mail);
        return true;
    }

    public boolean sendOtpBySMS(SmsDTO smsDTO) {
        Sms sms = Sms.newBuilder().setTo(smsDTO.to()).setMessage(smsDTO.message()).build();
        kafkaTemplate.send(smsTopicName, sms.getTo().toString(), sms);
        return true;
    }
}
