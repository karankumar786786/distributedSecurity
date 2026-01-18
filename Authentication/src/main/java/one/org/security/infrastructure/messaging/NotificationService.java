package one.org.security.infrastructure.messaging;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import one.org.security.core.domain.dto.MailDTO;
import one.org.security.core.domain.dto.SmsDTO;
import one.org.security.infrastructure.messageBroker.BrokerService;

@Service
public class NotificationService {

    @Autowired
    private BrokerService brokerService;

    public boolean sendOtpByMail(MailDTO mailDTO) {
        return brokerService.sendOtpByMail(mailDTO);
    }

    public boolean sendOtpBySMS(SmsDTO smsDTO) {
        return brokerService.sendOtpBySMS(smsDTO);
    }
}
