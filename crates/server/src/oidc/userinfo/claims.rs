use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// `OpenID` Connect Userinfo claims
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Userinfo {
    /// Subject - REQUIRED
    pub sub: String,

    /// Full name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Given name(s)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    /// Surname(s)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    /// Middle name(s)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,

    /// Casual name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,

    /// Preferred username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,

    /// Profile page URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    /// Profile picture URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    /// Web page or blog URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,

    /// Email address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Email verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// Gender
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,

    /// Birthdate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,

    /// Time zone
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,

    /// Locale
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Phone number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,

    /// Phone number verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,

    /// Address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,

    /// Updated at timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,

    /// Additional custom claims
    #[serde(flatten)]
    pub custom_claims: HashMap<String, serde_json::Value>,
}

/// Address claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// Filter userinfo claims based on requested scopes
#[must_use]
pub fn filter_claims_by_scope(mut user: Userinfo, scopes: &[String]) -> Userinfo {
    let profile_requested = scopes.iter().any(|scope| scope == "profile");
    let mut filtered = Userinfo {
        sub: user.sub.clone(),
        name: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        preferred_username: None,
        profile: None,
        picture: None,
        website: None,
        email: None,
        email_verified: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        phone_number: None,
        phone_number_verified: None,
        address: None,
        updated_at: None,
        custom_claims: HashMap::new(),
    };

    for scope in scopes {
        match scope.as_str() {
            "profile" => {
                filtered.name = user.name.take();
                filtered.family_name = user.family_name.take();
                filtered.given_name = user.given_name.take();
                filtered.middle_name = user.middle_name.take();
                filtered.nickname = user.nickname.take();
                filtered.preferred_username = user.preferred_username.take();
                filtered.profile = user.profile.take();
                filtered.picture = user.picture.take();
                filtered.website = user.website.take();
                filtered.gender = user.gender.take();
                filtered.birthdate = user.birthdate.take();
                filtered.zoneinfo = user.zoneinfo.take();
                filtered.locale = user.locale.take();
                filtered.updated_at = user.updated_at.take();
            }
            "email" => {
                filtered.email = user.email.take();
                filtered.email_verified = user.email_verified.take();
            }
            "address" => {
                filtered.address = user.address.take();
            }
            "phone" => {
                filtered.phone_number = user.phone_number.take();
                filtered.phone_number_verified = user.phone_number_verified.take();
            }
            _ => {}
        }
    }

    if profile_requested {
        filtered.custom_claims = user.custom_claims;
    }

    filtered
}
