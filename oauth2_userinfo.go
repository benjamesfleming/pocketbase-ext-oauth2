package oauth2

import (
	"net/http"
	"slices"

	"github.com/pkg/errors"
	"github.com/pocketbase/pocketbase/core"
)

// @ref https://openid.net/specs/openid-connect-core-1_0.html#Claims

type UserInfoClaims struct {
	// Subject
	// Identifier for the End-User at the Issuer.
	Sub string `json:"sub"`

	// Name
	// End-User's full name in displayable form including all name parts,
	// possibly including titles and suffixes, ordered according to the
	// End-User's locale and preferences.
	Name string `json:"name,omitempty"`

	// Given Name
	// Given name(s) or first name(s) of the End-User. Note that in some
	// cultures, people can have multiple given names; all can be present,
	// with the names being separated by space characters.
	GivenName string `json:"given_name,omitempty"`

	// Family Name
	// Surname(s) or last name(s) of the End-User. Note that in some
	// cultures, people can have multiple family names or no family name;
	// all can be present, with the names being separated by space
	// characters.
	FamilyName string `json:"family_name,omitempty"`

	// Middle Name
	// Middle name(s) of the End-User. Note that in some cultures, people
	// can have multiple middle names; all can be present, with the names
	// being separated by space characters.
	MiddleName string `json:"middle_name,omitempty"`

	// Nickname
	// Casual name of the End-User that may or may not be the same as the
	// given_name. For instance, a nickname value of Mike might be returned
	// alongside a given_name value of Michael.
	Nickname string `json:"nickname,omitempty"`

	// Preferred Username
	// Shorthand name by which the End-User wishes to be referred to at the
	// RP, such as janedoe or j.doe. This value MAY be any valid JSON string
	// including special characters such as @, /, or whitespace. The RP MUST
	// NOT rely upon this value being unique, as discussed in Section 5.7.
	PreferredUsername string `json:"preferred_username,omitempty"`

	// Profile
	// URL of the End-User's profile page. The contents of this Web page SHOULD
	// be about the End-User.
	Profile string `json:"profile,omitempty"`

	// Picture
	// URL of the End-User's profile picture. This URL MUST refer to an image
	// file (for example, a PNG, JPEG, or GIF image file), rather than to a
	// Web page containing an image. Note that this URL SHOULD specifically
	// reference a profile photo of the End-User suitable for displaying when
	// describing the End-User, rather than an arbitrary photo taken by the End-User.
	Picture string `json:"picture,omitempty"`

	// Website
	// URL of the End-User's Web page or blog. This Web page SHOULD contain
	// information published by the End-User or an organization that the End-User
	// is affiliated with.
	Website string `json:"website,omitempty"`

	// Email
	// End-User's preferred e-mail address. Its value MUST conform to the RFC 5322
	// addr-spec syntax. The RP MUST NOT rely upon this value being unique, as
	// discussed in Section 5.7.
	Email string `json:"email,omitempty"`

	// Email Verified
	// True if the End-User's e-mail address has been verified; otherwise false.
	// When this Claim Value is true, this means that the OP took affirmative steps
	// to ensure that this e-mail address was controlled by the End-User at the time
	// the verification was performed. The means by which an e-mail address is
	// verified is context specific, and dependent upon the trust framework or
	// contractual agreements within which the parties are operating.
	EmailVerified bool `json:"email_verified,omitempty"`

	// Gender
	// End-User's gender. Values defined by this specification are female and male.
	// Other values MAY be used when neither of the defined values are applicable.
	Gender string `json:"gender,omitempty"`

	// Birthdate
	// End-User's birthday, represented as an ISO 8601-1 [ISO8601‑1] YYYY-MM-DD format.
	// The year MAY be 0000, indicating that it is omitted. To represent only the year,
	// YYYY format is allowed. Note that depending on the underlying platform's date
	// elated function, providing just year can result in varying month and day, so the
	// implementers need to take this factor into account to correctly process the dates.
	Birthdate string `json:"birthdate,omitempty"`

	// ZoneInfo
	// String from IANA Time Zone Database [IANA.time‑zones] representing the End-User's
	// time zone. For example, Europe/Paris or America/Los_Angeles.
	ZoneInfo string `json:"zoneinfo,omitempty"`

	// Locale
	// End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically
	// an ISO 639 Alpha-2 [ISO639] language code in lowercase and an ISO 3166-1 Alpha-2
	// [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or
	// fr-CA. As a compatibility note, some implementations have used an underscore as
	// the separator rather than a dash, for example, en_US; Relying Parties MAY choose
	// to accept this locale syntax as well.
	Locale string `json:"locale,omitempty"`

	// Phone Number
	// End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of
	// this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400. If the phone number
	// contains an extension, it is RECOMMENDED that the extension be represented using the
	// RFC 3966 [RFC3966] extension syntax, for example, +1 (604) 555-1234;ext=5678.
	PhoneNumber string `json:"phone_number,omitempty"`

	// Phone Number Verified
	// True if the End-User's phone number has been verified; otherwise false. When this Claim
	// Value is true, this means that the OP took affirmative steps to ensure that this phone
	// number was controlled by the End-User at the time the verification was performed. The
	// means by which a phone number is verified is context specific, and dependent upon the
	// trust framework or contractual agreements within which the parties are operating. When
	// true, the phone_number Claim MUST be in E.164 format and any extensions MUST be
	// represented in RFC 3966 format.
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`

	// Address
	// End-User's preferred postal address. The value of the address member is a JSON [RFC8259]
	// structure containing some or all of the members defined in Section 5.1.1.
	Address *UserInfoAddressClaim `json:"address,omitempty"`

	// Updated At
	// Time the End-User's information was last updated. Its value is a JSON number representing
	// the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
	UpdatedAt int64 `json:"updated_at,omitempty"`
}

type UserInfoAddressClaim struct {
	// Formatted
	// Full mailing address, formatted for display or use on a mailing label. This field MAY
	// contain multiple lines, separated by newlines. Newlines can be represented either as a
	// carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
	Formatted string `json:"formatted,omitempty"`

	// Street Address
	// Full street address component, which MAY include house number, street name, Post Office Box,
	// and multi-line extended street address information. This field MAY contain multiple lines,
	// separated by newlines. Newlines can be represented either as a carriage return/line feed
	// pair ("\r\n") or as a single line feed character ("\n").
	StreetAddress string `json:"street_address,omitempty"`

	// Locality
	// City or locality component.
	Locality string `json:"locality,omitempty"`

	// Region
	// State, province, prefecture, or region component.
	Region string `json:"region,omitempty"`

	// Postal Code
	// Zip code or postal code component.
	PostalCode string `json:"postal_code,omitempty"`

	// Country
	// Country name component.
	Country string `json:"country,omitempty"`
}

func (a UserInfoAddressClaim) IsEmpty() bool {
	return a == UserInfoAddressClaim{}
}

//

// UserInfoClaimStrategy defines the interface for retrieving user info
// claims based on the request event and scopes. This allows for custom
// implementations to determine how user info claims are populated and
// returned in the /userinfo endpoint.
type UserInfoClaimStrategy interface {
	GetUserInfoClaims(e *core.RequestEvent, scopes []string) (interface{}, error)
}

//

type DefaultUserInfoClaimStrategy struct{}

// GetUserInfoClaims implements [UserInfoClaimStrategy].
func (d *DefaultUserInfoClaimStrategy) GetUserInfoClaims(e *core.RequestEvent, scopes []string) (interface{}, error) {
	ret := &UserInfoClaims{}

	// For the default strategy, we'll just try to populate the standard claims from
	// the user record based on the field names. This may produce some unexpected results
	// if the user collection fields don't match the standard claim names or format.

	// The "sub" claim is required and must be the user ID.
	ret.Sub = e.Auth.Id

	// PROFILE

	if slices.Contains(scopes, "profile") {
		if d.hasType(e, "name", core.FieldTypeText) {
			ret.Name = e.Auth.GetString("name")
		}
		if d.hasType(e, "given_name", core.FieldTypeText) {
			ret.GivenName = e.Auth.GetString("given_name")
		}
		if d.hasType(e, "family_name", core.FieldTypeText) {
			ret.FamilyName = e.Auth.GetString("family_name")
		}
		if d.hasType(e, "middle_name", core.FieldTypeText) {
			ret.MiddleName = e.Auth.GetString("middle_name")
		}
		if d.hasType(e, "nickname", core.FieldTypeText) {
			ret.Nickname = e.Auth.GetString("nickname")
		}
		if d.hasType(e, "preferred_username", core.FieldTypeText) {
			ret.PreferredUsername = e.Auth.GetString("preferred_username")
		}
		if d.hasType(e, "profile", core.FieldTypeText, core.FieldTypeURL) {
			ret.Profile = e.Auth.GetString("profile")
		}
		if d.hasType(e, "avatar", core.FieldTypeFile) {
			// Default to "avatar" field for picture claim by default since the defaultPocketBase
			// user collection uses "avatar" instead of "picture". This allows us to return a profile
			// picture URL by default without requiring any custom configuration.
			if fn := e.Auth.GetString("avatar"); len(fn) > 0 {
				ret.Picture = e.App.Settings().Meta.AppURL + "/api/files/" + e.Auth.BaseFilesPath() + "/" + fn
			}
		} else if d.hasType(e, "picture", core.FieldTypeText, core.FieldTypeURL) {
			ret.Picture = e.Auth.GetString("picture")
		}
		if d.hasType(e, "website", core.FieldTypeText, core.FieldTypeURL) {
			ret.Website = e.Auth.GetString("website")
		}
		if d.hasType(e, "gender", core.FieldTypeText) {
			ret.Gender = e.Auth.GetString("gender")
		}
		if d.hasType(e, "zoneinfo", core.FieldTypeText) {
			ret.ZoneInfo = e.Auth.GetString("zoneinfo")
		}
		if d.hasType(e, "locale", core.FieldTypeText) {
			ret.Locale = e.Auth.GetString("locale")
		}
		if d.hasType(e, "birthdate", core.FieldTypeDate, core.FieldTypeNumber) {
			ret.Birthdate = e.Auth.GetDateTime("birthdate").Time().Format("2006-01-02")
		} else if d.hasType(e, "dob", core.FieldTypeDate, core.FieldTypeNumber) {
			ret.Birthdate = e.Auth.GetDateTime("dob").Time().Format("2006-01-02")
		}
		if d.hasType(e, "updated", core.FieldTypeAutodate, core.FieldTypeDate, core.FieldTypeNumber) {
			ret.UpdatedAt = e.Auth.GetDateTime("updated").Time().Unix()
		} else if d.hasType(e, "updated_at", core.FieldTypeAutodate, core.FieldTypeDate, core.FieldTypeNumber) {
			ret.UpdatedAt = e.Auth.GetDateTime("updated_at").Time().Unix()
		}
	}

	// EMAIL

	if slices.Contains(scopes, "email") {
		if d.hasType(e, "email", core.FieldTypeText, core.FieldTypeEmail) {
			ret.Email = e.Auth.GetString("email")
		}
		if d.hasType(e, "verified", core.FieldTypeBool) {
			ret.EmailVerified = e.Auth.GetBool("verified")
		} else if d.hasType(e, "email_verified", core.FieldTypeBool, core.FieldTypeNumber) {
			ret.EmailVerified = e.Auth.GetBool("email_verified")
		}
	}

	// PHONE

	if slices.Contains(scopes, "phone") {
		if d.hasType(e, "phone_number", core.FieldTypeText) {
			ret.PhoneNumber = e.Auth.GetString("phone_number")
		}
		if d.hasType(e, "phone_number_verified", core.FieldTypeBool, core.FieldTypeNumber) {
			ret.PhoneNumberVerified = e.Auth.GetBool("phone_number_verified")
		}
	}

	// ADDRESS

	if slices.Contains(scopes, "address") {
		ret.Address = &UserInfoAddressClaim{}
		if d.hasType(e, "address_street", core.FieldTypeText) {
			ret.Address.StreetAddress = e.Auth.GetString("address_street")
		}
		if d.hasType(e, "address_locality", core.FieldTypeText) {
			ret.Address.Locality = e.Auth.GetString("address_locality")
		}
		if d.hasType(e, "address_region", core.FieldTypeText) {
			ret.Address.Region = e.Auth.GetString("address_region")
		}
		if d.hasType(e, "address_postal_code", core.FieldTypeText) {
			ret.Address.PostalCode = e.Auth.GetString("address_postal_code")
		}
		if d.hasType(e, "address_country", core.FieldTypeText) {
			ret.Address.Country = e.Auth.GetString("address_country")
		}
		if ret.Address.IsEmpty() {
			ret.Address = nil // don't return an empty address object
		}
	}

	return ret, nil
}

func (d *DefaultUserInfoClaimStrategy) hasType(e *core.RequestEvent, claimName string, requireClaimType ...string) bool {
	if f := e.Auth.Collection().Fields.GetByName(claimName); f != nil {
		if slices.Contains(requireClaimType, f.Type()) {
			return true
		}
	}
	return false
}

var _ UserInfoClaimStrategy = (*DefaultUserInfoClaimStrategy)(nil)

//

func api_OAuth2UserInfo(e *core.RequestEvent) error {

	// TODO: Support provided scopes to determine which claims to return.
	//       For now we will just return all claims that we can populate
	//       from the user record.
	scopes := []string{"openid", "profile", "address", "email"}

	info, err := GetOAuth2Config().UserInfoClaimStrategy.GetUserInfoClaims(e, scopes)
	if err != nil {
		return e.InternalServerError("", errors.Wrap(err, "GetUserInfoClaims"))
	} else {
		return e.JSON(http.StatusOK, info)
	}
}
