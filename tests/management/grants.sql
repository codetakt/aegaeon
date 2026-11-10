BEGIN;
CREATE FUNCTION pg_temp.assert_true(value boolean,label text) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN IF value IS DISTINCT FROM true THEN RAISE EXCEPTION 'assertion failed: %',label; END IF; END $f$;
INSERT INTO aegaeon.administrators(id,email,password_hash) VALUES
 ('00000000-0000-0000-0000-00000000000a','grant-a@example.invalid','fixture'),
 ('00000000-0000-0000-0000-00000000000b','grant-b@example.invalid','fixture'),
 ('00000000-0000-0000-0000-00000000000c','grant-c@example.invalid','fixture');
INSERT INTO aegaeon.teams(id,name) VALUES
 ('10000000-0000-0000-0000-000000000001','scope-a'),
 ('10000000-0000-0000-0000-000000000002','scope-b'),
 ('10000000-0000-0000-0000-000000000003','recreated');
INSERT INTO aegaeon.tenants(id,team_id,slug,name,region) VALUES
 ('20000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','scope-tenant','tenant','local');
-- This privileged fixture constructs grant records directly to test the SQL
-- evaluator; it does not claim deployment-bootstrap acceptance.
INSERT INTO management_authority.principals(installation_id,administrator_id,kind)
SELECT i.id,a.id,a.kind::text FROM management_authority.installation i CROSS JOIN aegaeon.administrators a WHERE a.email IN ('grant-a@example.invalid','grant-b@example.invalid','grant-c@example.invalid');
INSERT INTO management_authority.selectors(id,installation_id,mode,anchor_kind,anchor_id,anchor_incarnation)
SELECT '30000000-0000-0000-0000-000000000001',id,'current_and_future_descendants','installation',id,id
FROM management_authority.installation;
UPDATE management_authority.selectors SET state='active' WHERE state='preparing';
INSERT INTO management_authority.operation_receipts(operation_id,installation_id,caller_role_oid,caller_role_name,canonical_sha256,result)
SELECT '40000000-0000-0000-0000-000000000001',id,(SELECT oid FROM pg_roles WHERE rolname=session_user),session_user,
 sha256(convert_to('fixture','UTF8')),'{}'::jsonb FROM management_authority.installation;
INSERT INTO management_authority.grants(id,installation_id,principal_id,principal_kind,bootstrap_operation_id,
 use_selector_id,use_action_policy,use_actions,delegation_selector_id,delegation_action_policy,delegation_actions,
 acknowledged_registry_version,conditions,valid_from,expires_at,permanent)
SELECT '50000000-0000-0000-0000-000000000001',id,'00000000-0000-0000-0000-00000000000a','HUMAN',
 '40000000-0000-0000-0000-000000000001','30000000-0000-0000-0000-000000000001','enumerated',ARRAY['inventory.teams.read'],
 '30000000-0000-0000-0000-000000000001','enumerated',ARRAY['inventory.teams.read'],1,'{}',statement_timestamp(),NULL,true
FROM management_authority.installation;
INSERT INTO management_authority.grants(id,installation_id,principal_id,principal_kind,parent_id,captured_parent_epoch,
 use_selector_id,use_action_policy,use_actions,delegation_selector_id,delegation_action_policy,delegation_actions,
 acknowledged_registry_version,conditions,valid_from,expires_at,permanent)
SELECT '50000000-0000-0000-0000-000000000002',installation_id,'00000000-0000-0000-0000-00000000000b',principal_kind,id,delegation_epoch,
 use_selector_id,use_action_policy,use_actions,delegation_selector_id,delegation_action_policy,delegation_actions,
 acknowledged_registry_version,conditions,valid_from,expires_at,permanent FROM management_authority.grants
WHERE id='50000000-0000-0000-0000-000000000001';
INSERT INTO management_authority.grants(id,installation_id,principal_id,principal_kind,parent_id,captured_parent_epoch,
 use_selector_id,use_action_policy,use_actions,acknowledged_registry_version,conditions,valid_from,expires_at,permanent)
SELECT '50000000-0000-0000-0000-000000000003',installation_id,'00000000-0000-0000-0000-00000000000c',principal_kind,id,delegation_epoch,
 use_selector_id,use_action_policy,use_actions,acknowledged_registry_version,conditions,valid_from,expires_at,permanent
FROM management_authority.grants WHERE id='50000000-0000-0000-0000-000000000002';
CREATE FUNCTION pg_temp.auth() RETURNS jsonb LANGUAGE sql STABLE AS $f$
SELECT jsonb_build_object('principal_id','00000000-0000-0000-0000-00000000000c','principal_kind','HUMAN',
 'credential_id','60000000-0000-0000-0000-000000000001','authenticated_at',statement_timestamp(),
 'expires_at',statement_timestamp()+interval '10 minutes'); $f$;
CREATE FUNCTION pg_temp.allowed() RETURNS boolean LANGUAGE sql STABLE AS $f$
SELECT management_authority.grant_covers_v1('50000000-0000-0000-0000-000000000003',id,pg_temp.auth(),
 'inventory.teams.read','team','10000000-0000-0000-0000-000000000001',statement_timestamp()) FROM management_authority.installation; $f$;
SELECT pg_temp.assert_true(pg_temp.allowed(),'A-B-C live chain allows explicit team action');
SELECT pg_temp.assert_true(NOT management_authority.grant_covers_v1('50000000-0000-0000-0000-000000000003',id,pg_temp.auth(),
 'inventory.users.read','team','10000000-0000-0000-0000-000000000001',statement_timestamp()),'resource/action type confusion denied') FROM management_authority.installation;
DO $depth$
DECLARE predecessor uuid:='50000000-0000-0000-0000-000000000001'; next_id uuid; n integer;
BEGIN
  FOR n IN 14..21 LOOP
    next_id:=('50000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid;
    INSERT INTO management_authority.grants(id,installation_id,principal_id,principal_kind,parent_id,captured_parent_epoch,
      use_selector_id,use_action_policy,use_actions,delegation_selector_id,delegation_action_policy,delegation_actions,
      acknowledged_registry_version,conditions,valid_from,expires_at,permanent)
    SELECT next_id,installation_id,'00000000-0000-0000-0000-00000000000c',principal_kind,id,delegation_epoch,
      use_selector_id,use_action_policy,use_actions,delegation_selector_id,delegation_action_policy,delegation_actions,
      acknowledged_registry_version,conditions,valid_from,expires_at,permanent
    FROM management_authority.grants WHERE id=predecessor;
    predecessor:=next_id;
  END LOOP;
  PERFORM pg_temp.assert_true((SELECT management_authority.grant_covers_v1(predecessor,id,pg_temp.auth(),
    'inventory.teams.read','team','10000000-0000-0000-0000-000000000001',statement_timestamp()) FROM management_authority.installation),'eight delegation edges accepted');
  BEGIN
    INSERT INTO management_authority.grants(id,installation_id,principal_id,principal_kind,parent_id,captured_parent_epoch,
      use_selector_id,use_action_policy,use_actions,acknowledged_registry_version,conditions,valid_from,expires_at,permanent)
    SELECT '50000000-0000-0000-0000-000000000022',installation_id,principal_id,principal_kind,id,delegation_epoch,
      use_selector_id,use_action_policy,use_actions,acknowledged_registry_version,conditions,valid_from,expires_at,permanent
    FROM management_authority.grants WHERE id=predecessor;
    RAISE EXCEPTION 'ninth delegation edge accepted';
  EXCEPTION WHEN check_violation THEN NULL; END;
  BEGIN
    INSERT INTO management_authority.grants(id,installation_id,principal_id,principal_kind,parent_id,captured_parent_epoch,
      use_selector_id,use_action_policy,use_actions,acknowledged_registry_version,conditions,valid_from,expires_at,permanent)
    SELECT '50000000-0000-0000-0000-000000000023',installation_id,principal_id,principal_kind,id,delegation_epoch,
      use_selector_id,use_action_policy,ARRAY['inventory.teams.read','inventory.users.read'],acknowledged_registry_version,conditions,valid_from,expires_at,permanent
    FROM management_authority.grants WHERE id='50000000-0000-0000-0000-000000000001';
    RAISE EXCEPTION 'combined action envelope accepted';
  EXCEPTION WHEN check_violation THEN NULL; END;
END
$depth$;
SELECT pg_temp.assert_true(NOT management_authority.action_covers_v1('all_current_and_future',ARRAY[]::text[],'unknown.action'),'future action policy never authorizes unknown actions');
SELECT pg_temp.assert_true(NOT management_authority.conditions_hold_v1('{"unknown":true}',pg_temp.auth(),statement_timestamp()),'unknown conditions deny');
SELECT pg_temp.assert_true(NOT management_authority.conditions_hold_v1('{}',pg_temp.auth()-'expires_at',statement_timestamp()),'missing authentication expiry denies');
SELECT pg_temp.assert_true(NOT management_authority.conditions_hold_v1('{}',pg_temp.auth()||'{"expires_at":"infinity"}',statement_timestamp()),'infinite authentication expiry denies');
UPDATE management_authority.grants SET label='renamed',revision=revision+1 WHERE id='50000000-0000-0000-0000-000000000001';
SELECT pg_temp.assert_true(pg_temp.allowed(),'metadata-only parent change preserves child');
UPDATE aegaeon.administrators SET status='DISABLED' WHERE id='00000000-0000-0000-0000-00000000000a';
SELECT pg_temp.assert_true(NOT pg_temp.allowed(),'inactive ancestor principal denies');
UPDATE aegaeon.administrators SET status='ACTIVE' WHERE id='00000000-0000-0000-0000-00000000000a';
UPDATE management_authority.grants SET conditions='{"credential_kind":"HUMAN"}',revision=revision+1,delegation_epoch=delegation_epoch+1
WHERE id='50000000-0000-0000-0000-000000000001';
SELECT pg_temp.assert_true(NOT pg_temp.allowed(),'parent authority change invalidates descendant epoch');
DO $f$ BEGIN
 BEGIN UPDATE management_authority.grants SET captured_parent_epoch=2,revision=revision+1 WHERE id='50000000-0000-0000-0000-000000000002';
 RAISE EXCEPTION 'unexpected captured epoch rewrite'; EXCEPTION WHEN check_violation THEN NULL; END;
END $f$;
UPDATE management_authority.grants SET revoked_at=statement_timestamp(),revision=revision+1,delegation_epoch=delegation_epoch+1
WHERE id='50000000-0000-0000-0000-000000000001';
DO $f$ BEGIN
 BEGIN UPDATE management_authority.grants SET revoked_at=NULL,revision=revision+1,delegation_epoch=delegation_epoch+1 WHERE id='50000000-0000-0000-0000-000000000001';
 RAISE EXCEPTION 'unexpected revocation resurrection'; EXCEPTION WHEN check_violation THEN NULL; END;
END $f$;
INSERT INTO management_authority.selectors(id,installation_id,mode,anchor_kind,anchor_id,anchor_incarnation)
SELECT '30000000-0000-0000-0000-000000000002',installation_id,'current_descendants','team',resource_id,incarnation
FROM management_authority.current_resources WHERE resource_kind='team' AND resource_id='10000000-0000-0000-0000-000000000001';
INSERT INTO management_authority.selector_members SELECT '30000000-0000-0000-0000-000000000002',resource_kind,resource_id,incarnation
FROM management_authority.current_resources WHERE resource_kind='tenant';
UPDATE management_authority.selectors SET state='active' WHERE id='30000000-0000-0000-0000-000000000002';
SELECT pg_temp.assert_true(management_authority.selector_covers_v1('30000000-0000-0000-0000-000000000002',id,'tenant','20000000-0000-0000-0000-000000000001'),'current-only includes captured descendant') FROM management_authority.installation;
UPDATE aegaeon.tenants SET team_id='10000000-0000-0000-0000-000000000002' WHERE id='20000000-0000-0000-0000-000000000001';
SELECT pg_temp.assert_true(NOT management_authority.selector_covers_v1('30000000-0000-0000-0000-000000000002',id,'tenant','20000000-0000-0000-0000-000000000001'),'move out drops current-only coverage') FROM management_authority.installation;
INSERT INTO aegaeon.tenants(id,team_id,slug,name,region) VALUES
 ('20000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000001','new-tenant','new','local');
SELECT pg_temp.assert_true(NOT management_authority.selector_covers_v1('30000000-0000-0000-0000-000000000002',id,'tenant','20000000-0000-0000-0000-000000000002'),'current-only excludes later creation') FROM management_authority.installation;
SELECT pg_temp.assert_true(management_authority.selector_covers_v1('30000000-0000-0000-0000-000000000001',id,'tenant','20000000-0000-0000-0000-000000000002'),'future selector includes later creation') FROM management_authority.installation;
INSERT INTO management_authority.selectors(id,installation_id,mode,anchor_kind,anchor_id,anchor_incarnation)
SELECT '30000000-0000-0000-0000-000000000003',installation_id,'exact','team',resource_id,incarnation
FROM management_authority.current_resources WHERE resource_kind='team' AND resource_id='10000000-0000-0000-0000-000000000003';
UPDATE management_authority.selectors SET state='active' WHERE id='30000000-0000-0000-0000-000000000003';
DELETE FROM aegaeon.teams WHERE id='10000000-0000-0000-0000-000000000003';
INSERT INTO aegaeon.teams(id,name) VALUES('10000000-0000-0000-0000-000000000003','replacement');
SELECT pg_temp.assert_true(NOT management_authority.selector_covers_v1('30000000-0000-0000-0000-000000000003',id,'team','10000000-0000-0000-0000-000000000003'),'same UUID recreation cannot revive exact authority') FROM management_authority.installation;
INSERT INTO aegaeon.teams(id,name) VALUES('10000000-0000-0000-0000-000000000003','conflict') ON CONFLICT DO NOTHING;
SELECT pg_temp.assert_true((SELECT count(*)=1 FROM management_authority.resource_identities WHERE resource_kind='team' AND resource_id='10000000-0000-0000-0000-000000000003' AND live),'conflict-do-nothing preserves exactly one incarnation');
DO $f$ BEGIN
 BEGIN UPDATE aegaeon.teams SET id='10000000-0000-0000-0000-000000000099' WHERE id='10000000-0000-0000-0000-000000000003';
 RAISE EXCEPTION 'unexpected identity reassignment'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN UPDATE management_authority.installation SET id=gen_random_uuid();
 RAISE EXCEPTION 'unexpected installation reassignment'; EXCEPTION WHEN check_violation THEN NULL; END;
END $f$;
-- Inventory names are a bounded projection, not a new storage/input constraint.
-- This privileged SQL fixture checks the view; mounted tests cover API paging.
INSERT INTO aegaeon.environments(id,tenant_id,name,slug,issuer_host) VALUES
 ('21000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000002','projection','projection','projection.example.invalid');
DO $names$
DECLARE sample text; expected jsonb; projected jsonb; kind text; identity uuid; stored text;
BEGIN
  FOREACH sample IN ARRAY ARRAY['ordinary name',E'A \t\nB', 'A'||chr(1)||'B', '', '   ',
    repeat('a',1024),repeat('a',1025),repeat('é',512),repeat('é',513),repeat('🐙',256),repeat('🐙',257)] LOOP
    expected:=CASE WHEN octet_length(sample)<=1024 THEN to_jsonb(sample) ELSE 'null'::jsonb END;
    UPDATE aegaeon.teams SET name=sample WHERE id='10000000-0000-0000-0000-000000000001';
    UPDATE aegaeon.tenants SET name=sample WHERE id='20000000-0000-0000-0000-000000000002';
    UPDATE aegaeon.environments SET name=sample WHERE id='21000000-0000-0000-0000-000000000001';
    FOR kind,identity,stored IN
      SELECT 'team','10000000-0000-0000-0000-000000000001'::uuid,name FROM aegaeon.teams WHERE id='10000000-0000-0000-0000-000000000001'
      UNION ALL SELECT 'tenant','20000000-0000-0000-0000-000000000002'::uuid,name FROM aegaeon.tenants WHERE id='20000000-0000-0000-0000-000000000002'
      UNION ALL SELECT 'environment','21000000-0000-0000-0000-000000000001'::uuid,name FROM aegaeon.environments WHERE id='21000000-0000-0000-0000-000000000001'
    LOOP
      SELECT document INTO STRICT projected FROM management_authority.current_resources
        WHERE resource_kind=kind AND resource_id=identity;
      PERFORM pg_temp.assert_true(projected ? 'name' AND projected->'name'=expected,
        kind||' required nullable complete name at '||octet_length(sample)||' bytes');
      PERFORM pg_temp.assert_true(projected->>'id'=identity::text AND stored=sample,
        kind||' identity and full stored name preserved');
    END LOOP;
  END LOOP;
END
$names$;
ROLLBACK;
