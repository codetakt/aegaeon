TRUNCATE aegaeon.audit_events, aegaeon.teams CASCADE;
INSERT INTO aegaeon.teams (id,name,slug) VALUES ('00000000-0000-0000-0000-000000000001','Recovery fixture','recovery');
INSERT INTO aegaeon.tenants (id,team_id,slug,name,region)
 VALUES ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001','tenant','Tenant','local');
INSERT INTO aegaeon.environments (id,tenant_id,name,slug,issuer_host) VALUES
 ('00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000002','Target','target','target.test.invalid'),
 ('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000002','Control','control','control.test.invalid');
INSERT INTO aegaeon.configuration_versions
 (id,environment_id,version_number,configuration_hash,status,configuration_document) VALUES
 ('00000000-0000-0000-0000-000000000020','00000000-0000-0000-0000-000000000010',1,repeat('a',64),'ARCHIVED','{}'),
 ('00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000010',2,repeat('b',64),'ACTIVE','{}'),
 ('00000000-0000-0000-0000-000000000022','00000000-0000-0000-0000-000000000011',1,repeat('c',64),'ACTIVE','{}');
UPDATE aegaeon.environments SET active_configuration_version_id =
 CASE id WHEN '00000000-0000-0000-0000-000000000010'::uuid THEN '00000000-0000-0000-0000-000000000021'::uuid ELSE '00000000-0000-0000-0000-000000000022'::uuid END;
INSERT INTO aegaeon.oauth_profiles
 (id,environment_id,configuration_version_id,name,profile_type,allowed_grant_types,token_endpoint_auth_methods_allowed,expires_at)
 VALUES ('00000000-0000-0000-0000-000000000030','00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000020','Expired profile','DOWNSTREAM','{authorization_code}','{none}','2020-01-01');
INSERT INTO aegaeon.clients
 (id,environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,oauth_profile_id) VALUES
 ('00000000-0000-0000-0000-000000000040','00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000020','selected','Selected','PUBLIC','{https://client.test.invalid/cb}','{authorization_code}','{openid}','none','00000000-0000-0000-0000-000000000030'),
 ('00000000-0000-0000-0000-000000000041','00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000020','unselected','Unselected','PUBLIC','{https://client.test.invalid/cb}','{authorization_code}','{openid}','none',NULL),
 ('00000000-0000-0000-0000-000000000042','00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000022','other','Other','PUBLIC','{https://client.test.invalid/cb}','{authorization_code}','{openid}','none',NULL);
INSERT INTO aegaeon.connections
 (id,environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,status)
 VALUES ('00000000-0000-0000-0000-000000000050','00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000020','disabled','Disabled','https://upstream.test.invalid','upstream','DISABLED');
INSERT INTO aegaeon.client_secrets
 (id,environment_id,configuration_version_id,client_id,status,secret_hash,expires_at,revoked_at)
 VALUES ('00000000-0000-0000-0000-000000000060','00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000020','00000000-0000-0000-0000-000000000040','REVOKED','fixture-noncredential-hash','2020-01-01',now());
INSERT INTO aegaeon.runtime_keys
 (id,environment_id,configuration_version_id,usage,kid,algorithm,provider,status,public_jwk,key_handle,revoked_at)
 VALUES ('00000000-0000-0000-0000-000000000070','00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000020','JWT_ACCESS_TOKEN_SIGNING','fixture','EdDSA','databaseEncrypted','REVOKED','{}','fixture-nonkey-handle',now());
