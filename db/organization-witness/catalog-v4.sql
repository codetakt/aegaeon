WITH entries AS (
 SELECT 'schema' AS key,jsonb_build_object('owner',pg_get_userbyid(nspowner),'acl',COALESCE(nspacl::text,'')) AS value
 FROM pg_namespace WHERE nspname='organization_witness'
 UNION ALL
 SELECT 'table:'||c.relname,jsonb_build_object('kind',c.relkind,'owner',pg_get_userbyid(c.relowner),'acl',COALESCE(c.relacl::text,''),'rls',c.relrowsecurity,'force_rls',c.relforcerowsecurity)
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='organization_witness'
 UNION ALL
 SELECT 'column:'||c.relname||':'||a.attname,jsonb_build_object('type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid),'acl',COALESCE(a.attacl::text,''),'generated',a.attgenerated,'identity',a.attidentity,'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE a.attcollation::regcollation::text END)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE n.nspname='organization_witness' AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL
 SELECT 'constraint:'||c.relname||':'||k.conname,to_jsonb(pg_get_constraintdef(k.oid,true))
 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='organization_witness'
 UNION ALL
 SELECT 'function:'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',jsonb_build_object('definition',CASE WHEN octet_length(p.prosrc)<=32768 THEN pg_get_functiondef(p.oid) ELSE 'oversized function refused' END,'owner',pg_get_userbyid(p.proowner),'acl',COALESCE(p.proacl::text,''))
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='organization_witness'
 UNION ALL
 SELECT 'index:'||c.relname,jsonb_build_object('definition',pg_get_indexdef(i.indexrelid),'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive)
 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='organization_witness'
 UNION ALL
 SELECT 'trigger:'||c.relname||':'||t.tgname,to_jsonb(pg_get_triggerdef(t.oid,true))
 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='organization_witness' AND NOT t.tgisinternal
 UNION ALL
 SELECT 'rule:'||c.relname||':'||r.rulename,jsonb_build_object('definition',CASE WHEN octet_length(r.ev_action::text)<=32768 AND octet_length(r.ev_qual::text)<=32768 THEN pg_get_ruledef(r.oid,true) ELSE 'oversized rule refused' END,'enabled',r.ev_enabled)
 FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='organization_witness'

)
SELECT COALESCE(jsonb_object_agg(key,CASE WHEN octet_length(value::text)<=65536 THEN value ELSE '{"refused":"oversized entry"}'::jsonb END),'{}'::jsonb) FROM (SELECT key,value FROM entries ORDER BY key LIMIT 513) bounded
