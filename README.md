# Pocket Base OAuth2 Provider Plugin

Turn any pocketbase instance into an OAuth2 Authorization Server.

TODO:

- [ ] Add unit testing
- [ ] Use secure signing secret
- [ ] Use secure private key storage location(?)
- [ ] Encrypt session data in the DB(?)
- [ ] Cronjob to cleanup expired tokens
- [ ] Enable OAuth-based logins
- [ ] Add OAuth token/claims to RequestEvent or stash in context
- [ ] Add OAuth scope validation
- [ ] Implement OAuth2Store.ClientAssertionJWTValid
- [ ] Implement OAuth2Store.SetClientAssertionJWT