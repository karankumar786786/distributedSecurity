package one.org.security.core.domain.entity;

import org.springframework.data.mongodb.core.mapping.Field;

import com.yubico.webauthn.data.ByteArray;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FidoCredential {

    @Field("credential_id")
    private ByteArray credentialId;

    @Field("user_handle")
    private ByteArray userHandle;

    @Field("public_key")
    private ByteArray publicKey;

    @Field("signature_count")
    private long signatureCount;

    @Field("name")
    private String name; // e.g., "My MacBook"
}
