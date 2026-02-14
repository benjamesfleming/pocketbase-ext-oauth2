package oauth2

import (
	"time"

	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	fositeopenid "github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/pocketbase/pocketbase/core"
)

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field

// NewSession is a helper function for creating a new session. This may look like a lot of code but since we are
// setting up multiple strategies it is a bit longer.
// Usually, you could do:
//
//	session = new(fosite.DefaultSession)
func NewSession(app core.App, recordId string, collectionId string) *Session {
	return &Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Issuer:    app.Settings().Meta.AppURL,
				Subject:   recordId,
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(time.Hour * 6),
			},
			Headers:  &jwt.Headers{},
			Subject:  recordId,
			Username: "", // TODO: Add email here?
		},
		CollectionId: collectionId,
	}
}

type Session struct {
	fositeopenid.DefaultSession

	CollectionId string `json:"collection,omitempty"`
}

var _ fositeopenid.Session = (*Session)(nil)

func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	claims := &jwt.JWTClaims{}
	if s.Claims != nil {
		claims.FromMapClaims(s.Claims.ToMapClaims())
	}
	claims.Add("collection", s.CollectionId)
	return claims
}

func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	return deepcopy.Copy(s).(fosite.Session)
}
