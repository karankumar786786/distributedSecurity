# MongoDB Configuration Fix

## Issue

Authorization server was failing with MongoDB authentication error:

```
Command failed with error 13 (Unauthorized): 'Command find requires authentication'
```

## Root Cause

The Authorization service's `application.yaml` had the wrong MongoDB database name:

- **Incorrect**: `mongodb://admin:secret@localhost:27017/security?authSource=admin`
- **Correct**: `mongodb://admin:secret@localhost:27017/authorization?authSource=admin`

The service was trying to access the `security` database (used by Authentication service) instead of its own `authorization` database.

## Fix Applied

Updated [`Autherization/src/main/resources/application.yaml`](file:///Users/rahulgupta/Desktop/distributedSecurity/Autherization/src/main/resources/application.yaml):

```yaml
mongodb:
  uri: mongodb://admin:secret@localhost:27017/authorization?authSource=admin
```

## Next Steps

**Restart the Authorization server** to apply the configuration change:

```bash
# Stop the current Authorization server (Ctrl+C in terminal)
# Then restart:
cd /Users/rahulgupta/Desktop/distributedSecurity/Autherization
mvn spring-boot:run
```

## Expected Result

After restart, the Authorization server should:

- ✅ Connect to MongoDB successfully
- ✅ Load registered clients from the `authorization` database
- ✅ Process OAuth2 authorization requests
- ✅ Complete the OAuth2 flow with client applications

## Database Structure

| Service        | Database Name   | Purpose                                   |
| -------------- | --------------- | ----------------------------------------- |
| Authentication | `security`      | User accounts, sessions, FIDO credentials |
| Authorization  | `authorization` | OAuth2 clients, authorizations, tokens    |
| ResourceServer | N/A             | Stateless (validates tokens only)         |
