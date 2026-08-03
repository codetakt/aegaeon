module DCR
open EverParse3d.Prelude
open EverParse3d.Actions.All
open EverParse3d.Interpreter

module T = FStar.Tactics
module A = EverParse3d.Actions.All
module P = EverParse3d.Prelude
#set-options "--fuel 0 --ifuel 0 --ext optimize_let_vc"

[@@ specialize; noextract_to "krml"]
noextract
let def__client_metadata =
  ((T_dep_pair "redirect_uris_length"
        (DT_IType UInt32)
        (fun redirect_uris_length ->
            (T_pair "redirect_uris"
                false
                (T_with_comment "redirect_uris"
                    (T_nlist "redirect_uris"
                        redirect_uris_length
                        None
                        true
                        (T_denoted "redirect_uris.element" (DT_IType UInt8)))
                    " Concatenated URI strings;  Optional fields with presence flags")
                false
                (T_pair "has_token_endpoint_auth_method"
                    true
                    (T_with_comment "has_token_endpoint_auth_method"
                        (T_denoted "has_token_endpoint_auth_method" (DT_IType UInt8))
                        "Validating field has_token_endpoint_auth_method")
                    false
                    (T_pair "token_endpoint_auth_method"
                        true
                        (T_with_comment "token_endpoint_auth_method"
                            (T_denoted "token_endpoint_auth_method" (DT_IType UInt32))
                            " 0=none, 1=client_secret_post, 2=client_secret_basic, 3=private_key_jwt"
                        )
                        false
                        (T_pair "has_grant_types"
                            true
                            (T_with_comment "has_grant_types"
                                (T_denoted "has_grant_types" (DT_IType UInt8))
                                "Validating field has_grant_types")
                            false
                            (T_pair "grant_types"
                                true
                                (T_with_comment "grant_types"
                                    (T_denoted "grant_types" (DT_IType UInt32))
                                    " Bitmask: 1=authorization_code, 2=refresh_token, 4=client_credentials, 8=urn:ietf:params:oauth:grant-type:jwt-bearer"
                                )
                                false
                                (T_pair "has_response_types"
                                    true
                                    (T_with_comment "has_response_types"
                                        (T_denoted "has_response_types" (DT_IType UInt8))
                                        "Validating field has_response_types")
                                    false
                                    (T_pair "response_types"
                                        true
                                        (T_with_comment "response_types"
                                            (T_denoted "response_types" (DT_IType UInt32))
                                            " Bitmask: 1=code, 2=token (deprecated)")
                                        false
                                        (T_pair "has_client_name"
                                            true
                                            (T_with_comment "has_client_name"
                                                (T_denoted "has_client_name" (DT_IType UInt8))
                                                "Validating field has_client_name")
                                            false
                                            (T_dep_pair "client_name_length"
                                                (DT_IType UInt32)
                                                (fun client_name_length ->
                                                    (T_pair "client_name"
                                                        false
                                                        (T_with_comment "client_name"
                                                            (T_nlist "client_name"
                                                                client_name_length
                                                                None
                                                                true
                                                                (T_denoted "client_name.element"
                                                                    (DT_IType UInt8)))
                                                            "Validating field client_name")
                                                        false
                                                        (T_pair "has_client_uri"
                                                            true
                                                            (T_with_comment "has_client_uri"
                                                                (T_denoted "has_client_uri"
                                                                    (DT_IType UInt8))
                                                                "Validating field has_client_uri")
                                                            false
                                                            (T_dep_pair "client_uri_length"
                                                                (DT_IType UInt32)
                                                                (fun client_uri_length ->
                                                                    (T_pair "client_uri"
                                                                        false
                                                                        (T_with_comment "client_uri"
                                                                            (T_nlist "client_uri"
                                                                                client_uri_length
                                                                                None
                                                                                true
                                                                                (T_denoted
                                                                                    "client_uri.element"
                                                                                    (DT_IType UInt8)
                                                                                ))
                                                                            "Validating field client_uri"
                                                                        )
                                                                        false
                                                                        (T_pair "has_logo_uri"
                                                                            true
                                                                            (T_with_comment
                                                                                "has_logo_uri"
                                                                                (T_denoted
                                                                                    "has_logo_uri"
                                                                                    (DT_IType UInt8)
                                                                                )
                                                                                "Validating field has_logo_uri"
                                                                            )
                                                                            false
                                                                            (T_dep_pair
                                                                                "logo_uri_length"
                                                                                (DT_IType UInt32)
                                                                                (fun
                                                                                    logo_uri_length
                                                                                    ->
                                                                                    (T_pair
                                                                                        "logo_uri"
                                                                                        false
                                                                                        (T_with_comment
                                                                                            "logo_uri"
                                                                                            (T_nlist
                                                                                                "logo_uri"
                                                                                                logo_uri_length
                                                                                                None
                                                                                                true
                                                                                                (T_denoted
                                                                                                    "logo_uri.element"
                                                                                                    (
                                                                                                      DT_IType
                                                                                                      UInt8
                                                                                                    )
                                                                                                ))
                                                                                            "Validating field logo_uri"
                                                                                        )
                                                                                        false
                                                                                        (T_dep_pair
                                                                                            "scopes_length"
                                                                                            (DT_IType
                                                                                              UInt32
                                                                                            )
                                                                                            (fun
                                                                                                scopes_length
                                                                                                ->
                                                                                                (T_pair
                                                                                                    "scopes"
                                                                                                    false
                                                                                                    (
                                                                                                      T_with_comment
                                                                                                        "scopes"
                                                                                                        (
                                                                                                          T_nlist
                                                                                                            "scopes"
                                                                                                            scopes_length
                                                                                                            None
                                                                                                            true
                                                                                                            (
                                                                                                              T_denoted
                                                                                                                "scopes.element"
                                                                                                                (
                                                                                                                  DT_IType
                                                                                                                  UInt8
                                                                                                                )
                                                                                                            )
                                                                                                        )
                                                                                                        " Concatenated scope strings"
                                                                                                    )
                                                                                                    false
                                                                                                    (
                                                                                                      T_pair
                                                                                                        "has_contacts"
                                                                                                        true
                                                                                                        (
                                                                                                          T_with_comment
                                                                                                            "has_contacts"
                                                                                                            (
                                                                                                              T_denoted
                                                                                                                "has_contacts"
                                                                                                                (
                                                                                                                  DT_IType
                                                                                                                  UInt8
                                                                                                                )
                                                                                                            )
                                                                                                            "Validating field has_contacts"
                                                                                                        )
                                                                                                        false
                                                                                                        (
                                                                                                          T_dep_pair
                                                                                                            "contacts_length"
                                                                                                            (
                                                                                                              DT_IType
                                                                                                              UInt32
                                                                                                            )
                                                                                                            (
                                                                                                              fun
                                                                                                                contacts_length
                                                                                                                ->
                                                                                                                (
                                                                                                                  T_pair
                                                                                                                    "contacts"
                                                                                                                    false
                                                                                                                    (
                                                                                                                      T_with_comment
                                                                                                                        "contacts"
                                                                                                                        (
                                                                                                                          T_nlist
                                                                                                                            "contacts"
                                                                                                                            contacts_length
                                                                                                                            None
                                                                                                                            true
                                                                                                                            (
                                                                                                                              T_denoted
                                                                                                                                "contacts.element"
                                                                                                                                (
                                                                                                                                  DT_IType
                                                                                                                                  UInt8
                                                                                                                                )
                                                                                                                            )
                                                                                                                        )
                                                                                                                        " Concatenated email addresses"
                                                                                                                    )
                                                                                                                    false
                                                                                                                    (
                                                                                                                      T_pair
                                                                                                                        "has_tos_uri"
                                                                                                                        true
                                                                                                                        (
                                                                                                                          T_with_comment
                                                                                                                            "has_tos_uri"
                                                                                                                            (
                                                                                                                              T_denoted
                                                                                                                                "has_tos_uri"
                                                                                                                                (
                                                                                                                                  DT_IType
                                                                                                                                  UInt8
                                                                                                                                )
                                                                                                                            )
                                                                                                                            "Validating field has_tos_uri"
                                                                                                                        )
                                                                                                                        false
                                                                                                                        (
                                                                                                                          T_dep_pair
                                                                                                                            "tos_uri_length"
                                                                                                                            (
                                                                                                                              DT_IType
                                                                                                                              UInt32
                                                                                                                            )
                                                                                                                            (
                                                                                                                              fun
                                                                                                                                tos_uri_length
                                                                                                                                ->
                                                                                                                                (
                                                                                                                                  T_pair
                                                                                                                                    "tos_uri"
                                                                                                                                    false
                                                                                                                                    (
                                                                                                                                      T_with_comment
                                                                                                                                        "tos_uri"
                                                                                                                                        (
                                                                                                                                          T_nlist
                                                                                                                                            "tos_uri"
                                                                                                                                            tos_uri_length
                                                                                                                                            None
                                                                                                                                            true
                                                                                                                                            (
                                                                                                                                              T_denoted
                                                                                                                                                "tos_uri.element"
                                                                                                                                                (
                                                                                                                                                  DT_IType
                                                                                                                                                  UInt8
                                                                                                                                                )
                                                                                                                                            )
                                                                                                                                        )
                                                                                                                                        "Validating field tos_uri"
                                                                                                                                    )
                                                                                                                                    false
                                                                                                                                    (
                                                                                                                                      T_pair
                                                                                                                                        "has_policy_uri"
                                                                                                                                        true
                                                                                                                                        (
                                                                                                                                          T_with_comment
                                                                                                                                            "has_policy_uri"
                                                                                                                                            (
                                                                                                                                              T_denoted
                                                                                                                                                "has_policy_uri"
                                                                                                                                                (
                                                                                                                                                  DT_IType
                                                                                                                                                  UInt8
                                                                                                                                                )
                                                                                                                                            )
                                                                                                                                            "Validating field has_policy_uri"
                                                                                                                                        )
                                                                                                                                        false
                                                                                                                                        (
                                                                                                                                          T_dep_pair
                                                                                                                                            "policy_uri_length"
                                                                                                                                            (
                                                                                                                                              DT_IType
                                                                                                                                              UInt32
                                                                                                                                            )
                                                                                                                                            (
                                                                                                                                              fun
                                                                                                                                                policy_uri_length
                                                                                                                                                ->
                                                                                                                                                (
                                                                                                                                                  T_pair
                                                                                                                                                    "policy_uri"
                                                                                                                                                    false
                                                                                                                                                    (
                                                                                                                                                      T_with_comment
                                                                                                                                                        "policy_uri"
                                                                                                                                                        (
                                                                                                                                                          T_nlist
                                                                                                                                                            "policy_uri"
                                                                                                                                                            policy_uri_length
                                                                                                                                                            None
                                                                                                                                                            true
                                                                                                                                                            (
                                                                                                                                                              T_denoted
                                                                                                                                                                "policy_uri.element"
                                                                                                                                                                (
                                                                                                                                                                  DT_IType
                                                                                                                                                                  UInt8
                                                                                                                                                                )
                                                                                                                                                            )
                                                                                                                                                        )
                                                                                                                                                        "Validating field policy_uri"
                                                                                                                                                    )
                                                                                                                                                    false
                                                                                                                                                    (
                                                                                                                                                      T_pair
                                                                                                                                                        "has_jwks_uri"
                                                                                                                                                        true
                                                                                                                                                        (
                                                                                                                                                          T_with_comment
                                                                                                                                                            "has_jwks_uri"
                                                                                                                                                            (
                                                                                                                                                              T_denoted
                                                                                                                                                                "has_jwks_uri"
                                                                                                                                                                (
                                                                                                                                                                  DT_IType
                                                                                                                                                                  UInt8
                                                                                                                                                                )
                                                                                                                                                            )
                                                                                                                                                            "Validating field has_jwks_uri"
                                                                                                                                                        )
                                                                                                                                                        false
                                                                                                                                                        (
                                                                                                                                                          T_dep_pair
                                                                                                                                                            "jwks_uri_length"
                                                                                                                                                            (
                                                                                                                                                              DT_IType
                                                                                                                                                              UInt32
                                                                                                                                                            )
                                                                                                                                                            (
                                                                                                                                                              fun
                                                                                                                                                                jwks_uri_length
                                                                                                                                                                ->
                                                                                                                                                                (
                                                                                                                                                                  T_pair
                                                                                                                                                                    "jwks_uri"
                                                                                                                                                                    false
                                                                                                                                                                    (
                                                                                                                                                                      T_with_comment
                                                                                                                                                                        "jwks_uri"
                                                                                                                                                                        (
                                                                                                                                                                          T_nlist
                                                                                                                                                                            "jwks_uri"
                                                                                                                                                                            jwks_uri_length
                                                                                                                                                                            None
                                                                                                                                                                            true
                                                                                                                                                                            (
                                                                                                                                                                              T_denoted
                                                                                                                                                                                "jwks_uri.element"
                                                                                                                                                                                (
                                                                                                                                                                                  DT_IType
                                                                                                                                                                                  UInt8
                                                                                                                                                                                )
                                                                                                                                                                            )
                                                                                                                                                                        )
                                                                                                                                                                        "Validating field jwks_uri"
                                                                                                                                                                    )
                                                                                                                                                                    false
                                                                                                                                                                    (
                                                                                                                                                                      T_pair
                                                                                                                                                                        "has_software_id"
                                                                                                                                                                        true
                                                                                                                                                                        (
                                                                                                                                                                          T_with_comment
                                                                                                                                                                            "has_software_id"
                                                                                                                                                                            (
                                                                                                                                                                              T_denoted
                                                                                                                                                                                "has_software_id"
                                                                                                                                                                                (
                                                                                                                                                                                  DT_IType
                                                                                                                                                                                  UInt8
                                                                                                                                                                                )
                                                                                                                                                                            )
                                                                                                                                                                            "Validating field has_software_id"
                                                                                                                                                                        )
                                                                                                                                                                        false
                                                                                                                                                                        (
                                                                                                                                                                          T_dep_pair
                                                                                                                                                                            "software_id_length"
                                                                                                                                                                            (
                                                                                                                                                                              DT_IType
                                                                                                                                                                              UInt32
                                                                                                                                                                            )
                                                                                                                                                                            (
                                                                                                                                                                              fun
                                                                                                                                                                                software_id_length
                                                                                                                                                                                ->
                                                                                                                                                                                (
                                                                                                                                                                                  T_pair
                                                                                                                                                                                    "software_id"
                                                                                                                                                                                    false
                                                                                                                                                                                    (
                                                                                                                                                                                      T_with_comment
                                                                                                                                                                                        "software_id"
                                                                                                                                                                                        (
                                                                                                                                                                                          T_nlist
                                                                                                                                                                                            "software_id"
                                                                                                                                                                                            software_id_length
                                                                                                                                                                                            None
                                                                                                                                                                                            true
                                                                                                                                                                                            (
                                                                                                                                                                                              T_denoted
                                                                                                                                                                                                "software_id.element"
                                                                                                                                                                                                (
                                                                                                                                                                                                  DT_IType
                                                                                                                                                                                                  UInt8
                                                                                                                                                                                                )
                                                                                                                                                                                            )
                                                                                                                                                                                        )
                                                                                                                                                                                        "Validating field software_id"
                                                                                                                                                                                    )
                                                                                                                                                                                    false
                                                                                                                                                                                    (
                                                                                                                                                                                      T_pair
                                                                                                                                                                                        "has_software_version"
                                                                                                                                                                                        true
                                                                                                                                                                                        (
                                                                                                                                                                                          T_with_comment
                                                                                                                                                                                            "has_software_version"
                                                                                                                                                                                            (
                                                                                                                                                                                              T_denoted
                                                                                                                                                                                                "has_software_version"
                                                                                                                                                                                                (
                                                                                                                                                                                                  DT_IType
                                                                                                                                                                                                  UInt8
                                                                                                                                                                                                )
                                                                                                                                                                                            )
                                                                                                                                                                                            "Validating field has_software_version"
                                                                                                                                                                                        )
                                                                                                                                                                                        false
                                                                                                                                                                                        (
                                                                                                                                                                                          T_dep_pair
                                                                                                                                                                                            "software_version_length"
                                                                                                                                                                                            (
                                                                                                                                                                                              DT_IType
                                                                                                                                                                                              UInt32
                                                                                                                                                                                            )
                                                                                                                                                                                            (
                                                                                                                                                                                              fun
                                                                                                                                                                                                software_version_length
                                                                                                                                                                                                ->
                                                                                                                                                                                                (
                                                                                                                                                                                                  T_pair
                                                                                                                                                                                                    "software_version"
                                                                                                                                                                                                    false
                                                                                                                                                                                                    (
                                                                                                                                                                                                      T_with_comment
                                                                                                                                                                                                        "software_version"
                                                                                                                                                                                                        (
                                                                                                                                                                                                          T_nlist
                                                                                                                                                                                                            "software_version"
                                                                                                                                                                                                            software_version_length
                                                                                                                                                                                                            None
                                                                                                                                                                                                            true
                                                                                                                                                                                                            (
                                                                                                                                                                                                              T_denoted
                                                                                                                                                                                                                "software_version.element"
                                                                                                                                                                                                                (
                                                                                                                                                                                                                  DT_IType
                                                                                                                                                                                                                  UInt8
                                                                                                                                                                                                                )
                                                                                                                                                                                                            )
                                                                                                                                                                                                        )
                                                                                                                                                                                                        " OAuth 2.1 / RFC 9700 additions"
                                                                                                                                                                                                    )
                                                                                                                                                                                                    false
                                                                                                                                                                                                    (
                                                                                                                                                                                                      T_pair
                                                                                                                                                                                                        "requires_pkce"
                                                                                                                                                                                                        true
                                                                                                                                                                                                        (
                                                                                                                                                                                                          T_with_comment
                                                                                                                                                                                                            "requires_pkce"
                                                                                                                                                                                                            (
                                                                                                                                                                                                              T_denoted
                                                                                                                                                                                                                "requires_pkce"
                                                                                                                                                                                                                (
                                                                                                                                                                                                                  DT_IType
                                                                                                                                                                                                                  UInt8
                                                                                                                                                                                                                )
                                                                                                                                                                                                            )
                                                                                                                                                                                                            "Validating field requires_pkce"
                                                                                                                                                                                                        )
                                                                                                                                                                                                        false
                                                                                                                                                                                                        (
                                                                                                                                                                                                          T_pair
                                                                                                                                                                                                            "requires_dpop"
                                                                                                                                                                                                            true
                                                                                                                                                                                                            (
                                                                                                                                                                                                              T_with_comment
                                                                                                                                                                                                                "requires_dpop"
                                                                                                                                                                                                                (
                                                                                                                                                                                                                  T_denoted
                                                                                                                                                                                                                    "requires_dpop"
                                                                                                                                                                                                                    (
                                                                                                                                                                                                                      DT_IType
                                                                                                                                                                                                                      UInt8
                                                                                                                                                                                                                    )
                                                                                                                                                                                                                )
                                                                                                                                                                                                                "Validating field requires_dpop"
                                                                                                                                                                                                            )
                                                                                                                                                                                                            false
                                                                                                                                                                                                            (
                                                                                                                                                                                                              T_pair
                                                                                                                                                                                                                "requires_par"
                                                                                                                                                                                                                true
                                                                                                                                                                                                                (
                                                                                                                                                                                                                  T_with_comment
                                                                                                                                                                                                                    "requires_par"
                                                                                                                                                                                                                    (
                                                                                                                                                                                                                      T_denoted
                                                                                                                                                                                                                        "requires_par"
                                                                                                                                                                                                                        (
                                                                                                                                                                                                                          DT_IType
                                                                                                                                                                                                                          UInt8
                                                                                                                                                                                                                        )
                                                                                                                                                                                                                    )
                                                                                                                                                                                                                    " Sender-constrained token support"
                                                                                                                                                                                                                )
                                                                                                                                                                                                                false
                                                                                                                                                                                                                (
                                                                                                                                                                                                                  T_pair
                                                                                                                                                                                                                    "has_require_sender_constrained_tokens"
                                                                                                                                                                                                                    true
                                                                                                                                                                                                                    (
                                                                                                                                                                                                                      T_with_comment
                                                                                                                                                                                                                        "has_require_sender_constrained_tokens"
                                                                                                                                                                                                                        (
                                                                                                                                                                                                                          T_denoted
                                                                                                                                                                                                                            "has_require_sender_constrained_tokens"
                                                                                                                                                                                                                            (
                                                                                                                                                                                                                              DT_IType
                                                                                                                                                                                                                              UInt8
                                                                                                                                                                                                                            )
                                                                                                                                                                                                                        )
                                                                                                                                                                                                                        "Validating field has_require_sender_constrained_tokens"
                                                                                                                                                                                                                    )
                                                                                                                                                                                                                    false
                                                                                                                                                                                                                    (
                                                                                                                                                                                                                      T_pair
                                                                                                                                                                                                                        "require_sender_constrained_tokens"
                                                                                                                                                                                                                        true
                                                                                                                                                                                                                        (
                                                                                                                                                                                                                          T_with_comment
                                                                                                                                                                                                                            "require_sender_constrained_tokens"
                                                                                                                                                                                                                            (
                                                                                                                                                                                                                              T_denoted
                                                                                                                                                                                                                                "require_sender_constrained_tokens"
                                                                                                                                                                                                                                (
                                                                                                                                                                                                                                  DT_IType
                                                                                                                                                                                                                                  UInt8
                                                                                                                                                                                                                                )
                                                                                                                                                                                                                            )
                                                                                                                                                                                                                            "Validating field require_sender_constrained_tokens"
                                                                                                                                                                                                                        )
                                                                                                                                                                                                                        false
                                                                                                                                                                                                                        (
                                                                                                                                                                                                                          T_pair
                                                                                                                                                                                                                            "has_sender_constrained_methods"
                                                                                                                                                                                                                            true
                                                                                                                                                                                                                            (
                                                                                                                                                                                                                              T_with_comment
                                                                                                                                                                                                                                "has_sender_constrained_methods"
                                                                                                                                                                                                                                (
                                                                                                                                                                                                                                  T_denoted
                                                                                                                                                                                                                                    "has_sender_constrained_methods"
                                                                                                                                                                                                                                    (
                                                                                                                                                                                                                                      DT_IType
                                                                                                                                                                                                                                      UInt8
                                                                                                                                                                                                                                    )
                                                                                                                                                                                                                                )
                                                                                                                                                                                                                                "Validating field has_sender_constrained_methods"
                                                                                                                                                                                                                            )
                                                                                                                                                                                                                            false
                                                                                                                                                                                                                            (
                                                                                                                                                                                                                              T_dep_pair
                                                                                                                                                                                                                                "sender_constrained_methods_length"
                                                                                                                                                                                                                                (
                                                                                                                                                                                                                                  DT_IType
                                                                                                                                                                                                                                  UInt32
                                                                                                                                                                                                                                )
                                                                                                                                                                                                                                (
                                                                                                                                                                                                                                  fun
                                                                                                                                                                                                                                    sender_constrained_methods_length
                                                                                                                                                                                                                                    ->
                                                                                                                                                                                                                                    (
                                                                                                                                                                                                                                      T_pair
                                                                                                                                                                                                                                        "sender_constrained_methods"
                                                                                                                                                                                                                                        false
                                                                                                                                                                                                                                        (
                                                                                                                                                                                                                                          T_with_comment
                                                                                                                                                                                                                                            "sender_constrained_methods"
                                                                                                                                                                                                                                            (
                                                                                                                                                                                                                                              T_nlist
                                                                                                                                                                                                                                                "sender_constrained_methods"
                                                                                                                                                                                                                                                sender_constrained_methods_length
                                                                                                                                                                                                                                                None
                                                                                                                                                                                                                                                true
                                                                                                                                                                                                                                                (
                                                                                                                                                                                                                                                  T_denoted
                                                                                                                                                                                                                                                    "sender_constrained_methods.element"
                                                                                                                                                                                                                                                    (
                                                                                                                                                                                                                                                      DT_IType
                                                                                                                                                                                                                                                      UInt8
                                                                                                                                                                                                                                                    )
                                                                                                                                                                                                                                                )
                                                                                                                                                                                                                                            )
                                                                                                                                                                                                                                            " Method names"
                                                                                                                                                                                                                                        )
                                                                                                                                                                                                                                        true
                                                                                                                                                                                                                                        (
                                                                                                                                                                                                                                          T_pair
                                                                                                                                                                                                                                            "has_require_mtls"
                                                                                                                                                                                                                                            true
                                                                                                                                                                                                                                            (
                                                                                                                                                                                                                                              T_with_comment
                                                                                                                                                                                                                                                "has_require_mtls"
                                                                                                                                                                                                                                                (
                                                                                                                                                                                                                                                  T_denoted
                                                                                                                                                                                                                                                    "has_require_mtls"
                                                                                                                                                                                                                                                    (
                                                                                                                                                                                                                                                      DT_IType
                                                                                                                                                                                                                                                      UInt8
                                                                                                                                                                                                                                                    )
                                                                                                                                                                                                                                                )
                                                                                                                                                                                                                                                "Validating field has_require_mtls"
                                                                                                                                                                                                                                            )
                                                                                                                                                                                                                                            true
                                                                                                                                                                                                                                            (
                                                                                                                                                                                                                                              T_with_comment
                                                                                                                                                                                                                                                "require_mtls"
                                                                                                                                                                                                                                                (
                                                                                                                                                                                                                                                  T_denoted
                                                                                                                                                                                                                                                    "require_mtls"
                                                                                                                                                                                                                                                    (
                                                                                                                                                                                                                                                      DT_IType
                                                                                                                                                                                                                                                      UInt8
                                                                                                                                                                                                                                                    )
                                                                                                                                                                                                                                                )
                                                                                                                                                                                                                                                "Validating field require_mtls"
                                                                                                                                                                                                                                            )
                                                                                                                                                                                                                                        )
                                                                                                                                                                                                                                    )
                                                                                                                                                                                                                                )
                                                                                                                                                                                                                            )
                                                                                                                                                                                                                        )
                                                                                                                                                                                                                    )
                                                                                                                                                                                                                )
                                                                                                                                                                                                            )
                                                                                                                                                                                                        )
                                                                                                                                                                                                    )
                                                                                                                                                                                                )
                                                                                                                                                                                            )
                                                                                                                                                                                        )
                                                                                                                                                                                    )
                                                                                                                                                                                )
                                                                                                                                                                            )
                                                                                                                                                                        )
                                                                                                                                                                    )
                                                                                                                                                                )
                                                                                                                                                            )
                                                                                                                                                        )
                                                                                                                                                    )
                                                                                                                                                )
                                                                                                                                            )
                                                                                                                                        )
                                                                                                                                    )
                                                                                                                                )
                                                                                                                            )
                                                                                                                        )
                                                                                                                    )
                                                                                                                )
                                                                                                            )
                                                                                                        )
                                                                                                    )
                                                                                                ))))
                                                                                ))))))))))))))))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__client_metadata:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT32
        (and_then_kind (kind_nlist kind____UINT8 None)
            (and_then_kind kind____UINT8
                (and_then_kind kind____UINT32
                    (and_then_kind kind____UINT8
                        (and_then_kind kind____UINT32
                            (and_then_kind kind____UINT8
                                (and_then_kind kind____UINT32
                                    (and_then_kind kind____UINT8
                                        (and_then_kind kind____UINT32
                                            (and_then_kind (kind_nlist kind____UINT8 None)
                                                (and_then_kind kind____UINT8
                                                    (and_then_kind kind____UINT32
                                                        (and_then_kind (kind_nlist kind____UINT8
                                                                None)
                                                            (and_then_kind kind____UINT8
                                                                (and_then_kind kind____UINT32
                                                                    (and_then_kind (kind_nlist kind____UINT8
                                                                            None)
                                                                        (and_then_kind kind____UINT32
                                                                            (and_then_kind (kind_nlist
                                                                                    kind____UINT8
                                                                                    None)
                                                                                (and_then_kind kind____UINT8
                                                                                    (and_then_kind kind____UINT32
                                                                                        (and_then_kind
                                                                                            (kind_nlist
                                                                                                kind____UINT8
                                                                                                None
                                                                                            )
                                                                                            (and_then_kind
                                                                                                kind____UINT8
                                                                                                (and_then_kind
                                                                                                    kind____UINT32
                                                                                                    (
                                                                                                      and_then_kind
                                                                                                        (
                                                                                                          kind_nlist
                                                                                                            kind____UINT8
                                                                                                            None

                                                                                                        )
                                                                                                        (
                                                                                                          and_then_kind
                                                                                                            kind____UINT8
                                                                                                            (
                                                                                                              and_then_kind
                                                                                                                kind____UINT32
                                                                                                                (
                                                                                                                  and_then_kind
                                                                                                                    (
                                                                                                                      kind_nlist
                                                                                                                        kind____UINT8
                                                                                                                        None

                                                                                                                    )
                                                                                                                    (
                                                                                                                      and_then_kind
                                                                                                                        kind____UINT8
                                                                                                                        (
                                                                                                                          and_then_kind
                                                                                                                            kind____UINT32
                                                                                                                            (
                                                                                                                              and_then_kind
                                                                                                                                (
                                                                                                                                  kind_nlist
                                                                                                                                    kind____UINT8
                                                                                                                                    None

                                                                                                                                )
                                                                                                                                (
                                                                                                                                  and_then_kind
                                                                                                                                    kind____UINT8
                                                                                                                                    (
                                                                                                                                      and_then_kind
                                                                                                                                        kind____UINT32
                                                                                                                                        (
                                                                                                                                          and_then_kind
                                                                                                                                            (
                                                                                                                                              kind_nlist
                                                                                                                                                kind____UINT8
                                                                                                                                                None

                                                                                                                                            )
                                                                                                                                            (
                                                                                                                                              and_then_kind
                                                                                                                                                kind____UINT8
                                                                                                                                                (
                                                                                                                                                  and_then_kind
                                                                                                                                                    kind____UINT32
                                                                                                                                                    (
                                                                                                                                                      and_then_kind
                                                                                                                                                        (
                                                                                                                                                          kind_nlist
                                                                                                                                                            kind____UINT8
                                                                                                                                                            None

                                                                                                                                                        )
                                                                                                                                                        (
                                                                                                                                                          and_then_kind
                                                                                                                                                            kind____UINT8
                                                                                                                                                            (
                                                                                                                                                              and_then_kind
                                                                                                                                                                kind____UINT8
                                                                                                                                                                (
                                                                                                                                                                  and_then_kind
                                                                                                                                                                    kind____UINT8
                                                                                                                                                                    (
                                                                                                                                                                      and_then_kind
                                                                                                                                                                        kind____UINT8
                                                                                                                                                                        (
                                                                                                                                                                          and_then_kind
                                                                                                                                                                            kind____UINT8
                                                                                                                                                                            (
                                                                                                                                                                              and_then_kind
                                                                                                                                                                                kind____UINT8
                                                                                                                                                                                (
                                                                                                                                                                                  and_then_kind
                                                                                                                                                                                    kind____UINT32
                                                                                                                                                                                    (
                                                                                                                                                                                      and_then_kind
                                                                                                                                                                                        (
                                                                                                                                                                                          kind_nlist
                                                                                                                                                                                            kind____UINT8
                                                                                                                                                                                            None

                                                                                                                                                                                        )
                                                                                                                                                                                        (
                                                                                                                                                                                          and_then_kind
                                                                                                                                                                                            kind____UINT8
                                                                                                                                                                                            kind____UINT8

                                                                                                                                                                                        )

                                                                                                                                                                                    )

                                                                                                                                                                                )

                                                                                                                                                                            )

                                                                                                                                                                        )

                                                                                                                                                                    )

                                                                                                                                                                )

                                                                                                                                                            )

                                                                                                                                                        )

                                                                                                                                                    )

                                                                                                                                                )

                                                                                                                                            )

                                                                                                                                        )

                                                                                                                                    )

                                                                                                                                )

                                                                                                                            )

                                                                                                                        )

                                                                                                                    )

                                                                                                                )

                                                                                                            )

                                                                                                        )

                                                                                                    )
                                                                                                  ))
                                                                                        ))))))))))))
                                        ))))))))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__client_metadata:typ kind__client_metadata Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__client_metadata])))
    (def__client_metadata)

[@@ noextract_to "krml"]
noextract
let type__client_metadata = (as_type (def'__client_metadata))

[@@ noextract_to "krml"]
noextract
let parser__client_metadata = (as_parser (def'__client_metadata))
[@@ normalize_for_extraction specialization_steps; CInline]
let validate__client_metadata = as_validator "_client_metadata" (def'__client_metadata)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__client_metadata:dtyp kind__client_metadata false false Trivial Trivial Trivial =
  mk_dtyp_app kind__client_metadata Trivial Trivial Trivial (type__client_metadata)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__client_metadata]];
                  T.trefl ())))
        (parser__client_metadata)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%parser__client_metadata; `%type__client_metadata; `%coerce]];
                  T.trefl ())))
        (validate__client_metadata))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__registration_request =
  ((T_drop
      (T_pair "version"
          true
          (T_with_comment "version"
              (T_denoted "version" (DT_IType UInt32))
              " Protocol version (should be 1)")
          false
          (T_pair "metadata"
              false
              (T_with_comment "metadata"
                  (T_denoted "metadata" (dtyp__client_metadata))
                  " Optional initial access token reference")
              true
              (T_pair "has_initial_access_token"
                  true
                  (T_with_comment "has_initial_access_token"
                      (T_denoted "has_initial_access_token" (DT_IType UInt8))
                      "Validating field has_initial_access_token")
                  true
                  (T_with_comment "initial_access_token_id"
                      (T_denoted "initial_access_token_id" (DT_IType UInt32))
                      "Validating field initial_access_token_id")))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__registration_request:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT32
        (and_then_kind kind__client_metadata (and_then_kind kind____UINT8 kind____UINT32)))

[@@ specialize; noextract_to "krml"]
noextract
let def'__registration_request:typ kind__registration_request Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__registration_request])))
    (def__registration_request)

[@@ noextract_to "krml"]
noextract
let type__registration_request = (as_type (def'__registration_request))

[@@ noextract_to "krml"]
noextract
let parser__registration_request = (as_parser (def'__registration_request))
[@@ normalize_for_extraction specialization_steps]
let validate__registration_request =
  as_validator "_registration_request" (def'__registration_request)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__registration_request:dtyp kind__registration_request false false Trivial Trivial Trivial =
  mk_dtyp_app kind__registration_request Trivial Trivial Trivial (type__registration_request)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__registration_request]];
                  T.trefl ())))
        (parser__registration_request)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [
                          `%parser__registration_request;
                          `%type__registration_request;
                          `%coerce
                        ]
                    ];
                  T.trefl ())))
        (validate__registration_request))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__registration_response =
  ((T_drop
      (T_dep_pair "client_id_length"
          (DT_IType UInt32)
          (fun client_id_length ->
              (T_pair "client_id"
                  false
                  (T_with_comment "client_id"
                      (T_nlist "client_id"
                          client_id_length
                          None
                          true
                          (T_denoted "client_id.element" (DT_IType UInt8)))
                      "Validating field client_id")
                  false
                  (T_pair "has_client_secret"
                      true
                      (T_with_comment "has_client_secret"
                          (T_denoted "has_client_secret" (DT_IType UInt8))
                          "Validating field has_client_secret")
                      false
                      (T_dep_pair "client_secret_length"
                          (DT_IType UInt32)
                          (fun client_secret_length ->
                              (T_pair "client_secret"
                                  false
                                  (T_with_comment "client_secret"
                                      (T_nlist "client_secret"
                                          client_secret_length
                                          None
                                          true
                                          (T_denoted "client_secret.element" (DT_IType UInt8)))
                                      "Validating field client_secret")
                                  false
                                  (T_pair "client_id_issued_at"
                                      true
                                      (T_with_comment "client_id_issued_at"
                                          (T_denoted "client_id_issued_at" (DT_IType UInt32))
                                          " Unix timestamp")
                                      false
                                      (T_pair "has_client_secret_expires_at"
                                          true
                                          (T_with_comment "has_client_secret_expires_at"
                                              (T_denoted "has_client_secret_expires_at"
                                                  (DT_IType UInt8))
                                              "Validating field has_client_secret_expires_at")
                                          false
                                          (T_pair "client_secret_expires_at"
                                              true
                                              (T_with_comment "client_secret_expires_at"
                                                  (T_denoted "client_secret_expires_at"
                                                      (DT_IType UInt32))
                                                  " Unix timestamp or 0 for no expiry;  Echo back the registered metadata"
                                              )
                                              false
                                              (T_pair "registered_metadata"
                                                  false
                                                  (T_with_comment "registered_metadata"
                                                      (T_denoted "registered_metadata"
                                                          (dtyp__client_metadata))
                                                      " Registration management")
                                                  false
                                                  (T_pair "has_registration_access_token"
                                                      true
                                                      (T_with_comment
                                                          "has_registration_access_token"
                                                          (T_denoted "has_registration_access_token"
                                                              (DT_IType UInt8))
                                                          "Validating field has_registration_access_token"
                                                      )
                                                      false
                                                      (T_dep_pair "registration_access_token_length"
                                                          (DT_IType UInt32)
                                                          (fun registration_access_token_length ->
                                                              (T_pair "registration_access_token"
                                                                  false
                                                                  (T_with_comment
                                                                      "registration_access_token"
                                                                      (T_nlist
                                                                          "registration_access_token"
                                                                          registration_access_token_length
                                                                          None
                                                                          true
                                                                          (T_denoted
                                                                              "registration_access_token.element"
                                                                              (DT_IType UInt8)))
                                                                      "Validating field registration_access_token"
                                                                  )
                                                                  false
                                                                  (T_pair
                                                                      "has_registration_client_uri"
                                                                      true
                                                                      (T_with_comment
                                                                          "has_registration_client_uri"
                                                                          (T_denoted
                                                                              "has_registration_client_uri"
                                                                              (DT_IType UInt8))
                                                                          "Validating field has_registration_client_uri"
                                                                      )
                                                                      false
                                                                      (T_dep_pair
                                                                          "registration_client_uri_length"
                                                                          (DT_IType UInt32)
                                                                          (fun
                                                                              registration_client_uri_length
                                                                              ->
                                                                              (T_with_comment
                                                                                  "registration_client_uri"
                                                                                  (T_nlist
                                                                                      "registration_client_uri"
                                                                                      registration_client_uri_length
                                                                                      None
                                                                                      true
                                                                                      (T_denoted
                                                                                          "registration_client_uri.element"
                                                                                          (DT_IType
                                                                                            UInt8)))
                                                                                  "Validating field registration_client_uri"
                                                                              ))))))))))))))))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__registration_response:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT32
        (and_then_kind (kind_nlist kind____UINT8 None)
            (and_then_kind kind____UINT8
                (and_then_kind kind____UINT32
                    (and_then_kind (kind_nlist kind____UINT8 None)
                        (and_then_kind kind____UINT32
                            (and_then_kind kind____UINT8
                                (and_then_kind kind____UINT32
                                    (and_then_kind kind__client_metadata
                                        (and_then_kind kind____UINT8
                                            (and_then_kind kind____UINT32
                                                (and_then_kind (kind_nlist kind____UINT8 None)
                                                    (and_then_kind kind____UINT8
                                                        (and_then_kind kind____UINT32
                                                            (kind_nlist kind____UINT8 None))))))))))
                    )))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__registration_response:typ kind__registration_response Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (coerce_validator [`%kind__registration_response])))
    (def__registration_response)

[@@ noextract_to "krml"]
noextract
let type__registration_response = (as_type (def'__registration_response))

[@@ noextract_to "krml"]
noextract
let parser__registration_response = (as_parser (def'__registration_response))
[@@ normalize_for_extraction specialization_steps]
let validate__registration_response =
  as_validator "_registration_response" (def'__registration_response)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__registration_response:dtyp kind__registration_response false false Trivial Trivial Trivial =
  mk_dtyp_app kind__registration_response Trivial Trivial Trivial (type__registration_response)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__registration_response]];
                  T.trefl ())))
        (parser__registration_response)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [
                      delta_only [
                          `%parser__registration_response;
                          `%type__registration_response;
                          `%coerce
                        ]
                    ];
                  T.trefl ())))
        (validate__registration_response))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__update_request =
  ((T_drop
      (T_dep_pair "client_id_length"
          (DT_IType UInt32)
          (fun client_id_length ->
              (T_pair "client_id"
                  false
                  (T_with_comment "client_id"
                      (T_nlist "client_id"
                          client_id_length
                          None
                          true
                          (T_denoted "client_id.element" (DT_IType UInt8)))
                      "Validating field client_id")
                  false
                  (T_dep_pair "registration_access_token_length"
                      (DT_IType UInt32)
                      (fun registration_access_token_length ->
                          (T_pair "registration_access_token"
                              false
                              (T_with_comment "registration_access_token"
                                  (T_nlist "registration_access_token"
                                      registration_access_token_length
                                      None
                                      true
                                      (T_denoted "registration_access_token.element"
                                          (DT_IType UInt8)))
                                  "Validating field registration_access_token")
                              false
                              (T_with_comment "updated_metadata"
                                  (T_denoted "updated_metadata" (dtyp__client_metadata))
                                  "Validating field updated_metadata"))))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__update_request:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT32
        (and_then_kind (kind_nlist kind____UINT8 None)
            (and_then_kind kind____UINT32
                (and_then_kind (kind_nlist kind____UINT8 None) kind__client_metadata))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__update_request:typ kind__update_request Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ -> (coerce_validator [`%kind__update_request])
        ))
    (def__update_request)

[@@ noextract_to "krml"]
noextract
let type__update_request = (as_type (def'__update_request))

[@@ noextract_to "krml"]
noextract
let parser__update_request = (as_parser (def'__update_request))
[@@ normalize_for_extraction specialization_steps]
let validate__update_request = as_validator "_update_request" (def'__update_request)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__update_request:dtyp kind__update_request false false Trivial Trivial Trivial =
  mk_dtyp_app kind__update_request Trivial Trivial Trivial (type__update_request)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__update_request]];
                  T.trefl ())))
        (parser__update_request)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%parser__update_request; `%type__update_request; `%coerce]];
                  T.trefl ())))
        (validate__update_request))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))

[@@ specialize; noextract_to "krml"]
noextract
let def__error_response =
  ((T_drop
      (T_pair "error_code"
          true
          (T_with_comment "error_code"
              (T_denoted "error_code" (DT_IType UInt32))
              " 0=invalid_redirect_uri, 1=invalid_client_metadata, 2=invalid_software_statement")
          false
          (T_pair "has_error_description"
              true
              (T_with_comment "has_error_description"
                  (T_denoted "has_error_description" (DT_IType UInt8))
                  "Validating field has_error_description")
              false
              (T_dep_pair "error_description_length"
                  (DT_IType UInt32)
                  (fun error_description_length ->
                      (T_pair "error_description"
                          false
                          (T_with_comment "error_description"
                              (T_nlist "error_description"
                                  error_description_length
                                  None
                                  true
                                  (T_denoted "error_description.element" (DT_IType UInt8)))
                              "Validating field error_description")
                          false
                          (T_pair "has_error_uri"
                              true
                              (T_with_comment "has_error_uri"
                                  (T_denoted "has_error_uri" (DT_IType UInt8))
                                  "Validating field has_error_uri")
                              false
                              (T_dep_pair "error_uri_length"
                                  (DT_IType UInt32)
                                  (fun error_uri_length ->
                                      (T_with_comment "error_uri"
                                          (T_nlist "error_uri"
                                              error_uri_length
                                              None
                                              true
                                              (T_denoted "error_uri.element" (DT_IType UInt8)))
                                          "Validating field error_uri"))))))))))
    <:
    Tot (typ _ _ _ _ _ _)
    by
    (T.norm [delta_attr [`%specialize]; zeta; iota; primops];
      T.smt ()))

[@@ noextract_to "krml"]
inline_for_extraction noextract
let kind__error_response:P.parser_kind true WeakKindStrongPrefix =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%weak_kind_glb]; zeta; iota; primops];
              T.trefl ())))
    (and_then_kind kind____UINT32
        (and_then_kind kind____UINT8
            (and_then_kind kind____UINT32
                (and_then_kind (kind_nlist kind____UINT8 None)
                    (and_then_kind kind____UINT8
                        (and_then_kind kind____UINT32 (kind_nlist kind____UINT8 None)))))))

[@@ specialize; noextract_to "krml"]
noextract
let def'__error_response:typ kind__error_response Trivial Trivial Trivial false false =
  coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ -> (coerce_validator [`%kind__error_response])
        ))
    (def__error_response)

[@@ noextract_to "krml"]
noextract
let type__error_response = (as_type (def'__error_response))

[@@ noextract_to "krml"]
noextract
let parser__error_response = (as_parser (def'__error_response))
[@@ normalize_for_extraction specialization_steps]
let validate__error_response = as_validator "_error_response" (def'__error_response)

[@@ specialize; noextract_to "krml"]
noextract
let dtyp__error_response:dtyp kind__error_response false false Trivial Trivial Trivial =
  mk_dtyp_app kind__error_response Trivial Trivial Trivial (type__error_response)
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%type__error_response]];
                  T.trefl ())))
        (parser__error_response)) None false false
    (coerce (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
                (T.norm [delta_only [`%parser__error_response; `%type__error_response; `%coerce]];
                  T.trefl ())))
        (validate__error_response))
    (FStar.Tactics.Effect.synth_by_tactic (fun _ ->
            (T.norm [delta_only [`%Some?]; iota];
              T.trefl ())))
