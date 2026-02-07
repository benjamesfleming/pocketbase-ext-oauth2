package oauth2

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

func api_OAuth2Introspect(e *core.RequestEvent) error {
	r := e.Request
	w := e.Response
	ctx := r.Context()
	mySessionData := newSession(e.App, "", "")
	ir, err := oauth2.NewIntrospectionRequest(ctx, r, mySessionData)
	if err != nil {
		e.App.Logger().Info("[Plugin/OAuth2] Error occurred in NewIntrospectionRequest", slog.Any("error", err))
		var rfc6749err *fosite.RFC6749Error
		if errors.As(err, &rfc6749err) {
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %s", rfc6749err.DebugField))
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %+v", rfc6749err.StackTrace()))
		}
		oauth2.WriteIntrospectionError(ctx, w, err)
		return nil
	}
	oauth2.WriteIntrospectionResponse(ctx, w, ir)
	return nil
}
