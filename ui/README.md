Pocket Base OAuth2 Login/Consent UI

This is a temporary UI implementation for the OAuth2 login and consent screens. It uses the same markup as the existing Pocket Base UI to allow for a consistent look and feel using a shared stylesheet. Once the [UI rewrite](https://github.com/pocketbase/pocketbase/discussions/7287) is complete, this implementation will be removed and replaced.

This UI uses Alpine.js. It is embedded directly into the plugin's Go code and served as static assets. The UI is passed props via a base64url-encoded state parameter in the query strings.

```json
{
    "collection": "users",
    "client_id": "abc123",
    "client_name": "Example Client",
    "requested_scopes": ["read", "write"],
    "redirect_uri": "https://example.com/callback"
}
```