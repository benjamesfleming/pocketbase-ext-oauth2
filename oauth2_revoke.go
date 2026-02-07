package oauth2

import (
	"fmt"
	"log/slog"

	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

func api_OAuth2Revoke(e *core.RequestEvent) error {
	r := e.Request
	w := e.Response
	// This context will be passed to all methods.
	ctx := r.Context()
	// This will accept the token revocation request and validate various parameters.
	// All done, send the response.
	err := oauth2.NewRevocationRequest(ctx, r)
	if err != nil {
		e.App.Logger().Info("[Plugin/OAuth2] Error occurred in NewRevocationRequest", slog.Any("error", err))
		if rfc6749err, ok := err.(*fosite.RFC6749Error); ok {
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %s", rfc6749err.DebugField))
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %+v", rfc6749err.StackTrace()))
		}
	}
	oauth2.WriteRevocationResponse(ctx, w, err)
	return nil
}
