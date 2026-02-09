package rfc9728

import (
	"fmt"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
)

func RequireAuthRFC9728WWWAuthenticateResponse() *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Func: func(e *core.RequestEvent) error {
			if e.Auth == nil {
				e.Request.Header.Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, e.App.Settings().Meta.AppURL))
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
