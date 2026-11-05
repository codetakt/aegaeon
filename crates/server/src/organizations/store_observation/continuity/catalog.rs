//! Validate once per owned connection, independently of the legacy subject catalog.
use super::{migration, Error, Result};
use serde_json::{json, Value};

const QUERY: &str = r#"
SELECT pg_catalog.jsonb_build_object(
 'table',(SELECT pg_catalog.jsonb_build_object(
  'kind',c.relkind,'persistence',c.relpersistence,'owner',r.rolname,
  'owner_safe',NOT(r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls),
  'row_security',c.relrowsecurity OR c.relforcerowsecurity,'options',c.reloptions,
  'inherits',EXISTS(SELECT FROM pg_catalog.pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid),
  'rules',EXISTS(SELECT FROM pg_catalog.pg_rewrite WHERE ev_class=c.oid),
  'triggers',EXISTS(SELECT FROM pg_catalog.pg_trigger WHERE tgrelid=c.oid),
  'private_acl',NOT EXISTS(SELECT FROM pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a WHERE a.grantee<>c.relowner)
    AND NOT EXISTS(SELECT FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) x WHERE a.attrelid=c.oid AND x.grantee<>c.relowner),
  'columns',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,
    pg_catalog.pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated,a.attcollation::integer) ORDER BY a.attnum)
    FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
    WHERE a.attrelid=c.oid AND a.attnum>0),
  'constraints',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(x.conname,pg_catalog.pg_get_constraintdef(x.oid),x.convalidated,x.conislocal,x.coninhcount)
    ORDER BY x.conname COLLATE "C") FROM pg_catalog.pg_constraint x WHERE x.conrelid=c.oid AND x.contype<>'n'),
  'indexes',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(pg_catalog.pg_get_indexdef(i.indexrelid),i.indisunique,i.indisprimary,
    i.indisvalid,i.indisready,i.indislive,i.indimmediate,i.indisexclusion,pg_catalog.pg_get_expr(i.indpred,i.indrelid),
    pg_catalog.pg_get_expr(i.indexprs,i.indrelid)) ORDER BY i.indexrelid) FROM pg_catalog.pg_index i WHERE i.indrelid=c.oid)
 ) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
 WHERE n.nspname='aegaeon' AND c.relname='organization_store_continuity'),
 'functions',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
  'name',p.proname,'arguments',pg_catalog.oidvectortypes(p.proargtypes),'result',pg_catalog.pg_get_function_result(p.oid),
  'body',p.prosrc,'owner',r.rolname,'definer',p.prosecdef,'language',l.lanname,'volatility',p.provolatile,
  'strict',p.proisstrict,'set',p.proretset,'kind',p.prokind,'parallel',p.proparallel,'leakproof',p.proleakproof,
  'defaults',pg_catalog.pg_get_expr(p.proargdefaults,0),'settings',p.proconfig,
  'acl',pg_catalog.has_function_privilege('aegaeon_subject_maintenance',p.oid,'EXECUTE') AND NOT EXISTS(
    SELECT FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
    WHERE a.privilege_type<>'EXECUTE' OR (a.grantee<>p.proowner AND a.is_grantable)
      OR (a.grantee NOT IN (p.proowner,'aegaeon_subject_maintenance'::regrole) AND NOT EXISTS(
        SELECT FROM pg_catalog.pg_proc entry CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(entry.proacl,pg_catalog.acldefault('f',entry.proowner))) allowed
        JOIN pg_catalog.pg_roles runtime ON runtime.oid=allowed.grantee
        WHERE entry.oid=pg_catalog.to_regprocedure('aegaeon.validate_subject_ownership_namespace_v1(uuid)')
          AND allowed.grantee=a.grantee AND allowed.grantee<>entry.proowner
          AND allowed.privilege_type='EXECUTE' AND NOT allowed.is_grantable AND runtime.rolcanlogin
          AND NOT(runtime.rolsuper OR runtime.rolcreatedb OR runtime.rolcreaterole OR runtime.rolreplication OR runtime.rolbypassrls))))
 ) ORDER BY p.proname COLLATE "C") FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_catalog.pg_roles r ON r.oid=p.proowner JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE n.nspname='aegaeon' AND p.proname IN ('organization_store_continuity_read_v1','organization_store_continuity_replace_v1')))
"#;

fn function(name: &str, arguments: &str, volatility: &str) -> Result<Value> {
    let marker = format!("CREATE FUNCTION aegaeon.{name}(");
    let body = migration()
        .split_once(marker.as_str())
        .and_then(|(_, rest)| rest.split_once("AS $function$"))
        .and_then(|(_, rest)| rest.split_once("$function$;"))
        .map(|(body, _)| body)
        .ok_or(Error::Refused)?;
    Ok(
        json!({"name":name,"arguments":arguments,"result":"uuid","body":body,
        "owner":"aegaeon_subject_owner","definer":true,"language":"plpgsql","volatility":volatility,
        "strict":false,"set":false,"kind":"f","parallel":"u","leakproof":false,"defaults":null,
        "settings":["search_path=pg_catalog, pg_temp"],"acl":true}),
    )
}

fn expected() -> Result<Value> {
    Ok(json!({"table":{
        "kind":"r","persistence":"p","owner":"aegaeon_subject_owner","owner_safe":true,
        "row_security":false,"options":null,"inherits":false,"rules":false,"triggers":false,"private_acl":true,
        "columns":[["singleton","boolean",true,"true","","",0],["deployment_id","uuid",true,null,"","",0],
            ["seal","uuid",true,null,"","",0]],
        "constraints":[
            ["organization_store_continuity_deployment","CHECK ((deployment_id <> '00000000-0000-0000-0000-000000000000'::uuid))",true,true,0],
            ["organization_store_continuity_pkey","PRIMARY KEY (singleton)",true,true,0],
            ["organization_store_continuity_seal","CHECK ((seal <> '00000000-0000-0000-0000-000000000000'::uuid))",true,true,0],
            ["organization_store_continuity_singleton","CHECK (singleton)",true,true,0]],
        "indexes":[["CREATE UNIQUE INDEX organization_store_continuity_pkey ON aegaeon.organization_store_continuity USING btree (singleton)",
            true,true,true,true,true,true,false,null,null]]},
        "functions":[function("organization_store_continuity_read_v1","uuid","s")?,
            function("organization_store_continuity_replace_v1","uuid, uuid, uuid","v")?]}))
}

pub(in crate::organizations::store_observation) async fn check(
    connection: &mut sqlx::PgConnection,
) -> Result<()> {
    let actual: Value = sqlx::query_scalar(QUERY).fetch_one(connection).await?;
    if actual != expected()? {
        return Err(Error::Refused);
    }
    Ok(())
}
