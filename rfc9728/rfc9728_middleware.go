package rfc9728

import (
	"fmt"
	"strings"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
)

func RequireAuthRFC9728WWWAuthenticateResponse() *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Func: func(e *core.RequestEvent) error {
			if e.Auth == nil {
				resourceMetadataURL := fmt.Sprintf(
					"%s/.well-known/oauth-protected-resource/%s",
					strings.Trim(e.App.Settings().Meta.AppURL, "/"),
					strings.Trim(e.Request.URL.Path, "/"),
				)

				e.Response.Header().Add("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons.", resource_metadata="%s"`, resourceMetadataURL))
				e.Response.WriteHeader(401)
				return nil
			}
			return e.Next()
		},
		// Make sure this runs after the default LoadAuthToken middleware.
		// This is required to ensure that e.Auth is populated before this
		// hook is called.
		Priority: apis.DefaultLoadAuthTokenMiddlewarePriority + 10,
	}
}
