# Pocket Base OAuth2 Provider Plugin

Turn any pocketbase instance into an OAuth2 Authorization Server.

TODO:

- [ ] Add unit testing
- [x] Use secure signing secret
- [x] Use secure private key storage location(?)
- [ ] Encrypt session data in the DB(?)
- [x] Cronjob to cleanup expired tokens
- [ ] Enable OAuth-based logins
- [x] Implement OAuth2Store.ClientAssertionJWTValid
- [x] Implement OAuth2Store.SetClientAssertionJWT
- [ ] ~~Add OAuth token/claims to RequestEvent or stash in context~~
    - Access Token switched to regular PB auth token which doesn't support custom claims
- [ ] ~~Add OAuth scope validation~~
    - Access Token switched to regular PB auth token which doesn't support scopes