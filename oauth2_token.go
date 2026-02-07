package oauth2

import (
	"fmt"
	"log/slog"

	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

func api_OAuth2Token(e *core.RequestEvent) error {
	r := e.Request
	w := e.Response
	// This context will be passed to all methods.
	ctx := r.Context()
	// Create an empty session object which will be passed to the request handlers
	mySessionData := newSession(e.App, "", "")
	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	accessRequest, err := oauth2.NewAccessRequest(ctx, r, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		e.App.Logger().Info("[Plugin/OAuth2] Error occurred in NewAccessRequest", slog.Any("error", err))
		if rfc6749err, ok := err.(*fosite.RFC6749Error); ok {
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %s", rfc6749err.DebugField))
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %+v", rfc6749err.StackTrace()))
		}
		oauth2.WriteAccessError(ctx, w, accessRequest, err)
		return nil
	}

	// If this is a client_credentials grant, grant all requested scopes
	// NewAccessRequest validated that all requested scopes the client is allowed to perform
	// based on configured scope matching strategy.
	if accessRequest.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range accessRequest.GetRequestedScopes() {
			accessRequest.GrantScope(scope)
		}
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := oauth2.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		e.App.Logger().Info("[Plugin/OAuth2] Error occurred in NewAccessResponse", slog.Any("error", err))
		if rfc6749err, ok := err.(*fosite.RFC6749Error); ok {
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %s", rfc6749err.DebugField))
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %+v", rfc6749err.StackTrace()))
		}
		oauth2.WriteAccessError(ctx, w, accessRequest, err)
		return nil
	}

	// All done, send the response.
	// The client now has a valid access token
	oauth2.WriteAccessResponse(ctx, w, accessRequest, response)
	return nil
}
