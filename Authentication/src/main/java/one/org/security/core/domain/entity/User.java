package one.org.security.core.domain.entity;

import java.time.LocalDateTime;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.mongodb.lang.NonNull;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Document(collection = "security")
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class User implements UserDetails {

    @Id
    private ObjectId id;
    @NonNull
    @Indexed(unique = true)
    private String username;
    private String password;
    private String backupEmail;
    private boolean isAccountLocked;
    private List<String> knownDeviceHashes;
    private boolean passkeyEnabled;
    private boolean backupEmailVerified;
    private boolean phoneNumberVerified;
    private String phoneNumber;
    private LocalDateTime lockingTime;
    private int numberOfInitaiatedOperations;

    private FidoCredential fidoCredential;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !isAccountLocked; // Connects your field to the framework
    }

}
