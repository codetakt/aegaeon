import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {webcrypto, createHash} from 'node:crypto';

export async function checkDpopTimePolicyBounds(source, fixture) {
  const wasmBytes = fs.readFileSync(fixture);
  const manifest = {sha256:createHash('sha256').update(wasmBytes).digest('hex'),size_bytes:wasmBytes.length};
  const u64Max = (1n << 64n) - 1n;
  const u32Max = 0xffff_ffff;
  const validTimes = [
    ['bigint-zero',0n], ['bigint-one',1n], ['bigint-u64-max',u64Max],
    ['number-zero',0], ['number-one',1], ['number-2^53',2 ** 53],
    ['number-2^53+2',2 ** 53 + 2], ['number-2^63',2 ** 63],
    ['number-largest-below-2^64',2 ** 64 - 2048],
  ];
  const invalidTimes = [
    ['negative-number',-1], ['negative-bigint',-1n],
    ['bigint-2^64',1n << 64n], ['number-2^64',2 ** 64],
    ['NaN',NaN], ['infinity',Infinity], ['negative-infinity',-Infinity],
    ['fraction',0.5], ['string','1'], ['boolean',true], ['object',{}],
  ];
  const validPolicies = [['zero',0], ['one',1], ['u32-max',u32Max]];
  const invalidPolicies = [
    ['negative',-1], ['2^32',2 ** 32], ['NaN',NaN], ['infinity',Infinity],
    ['negative-infinity',-Infinity], ['fraction',0.5], ['string','1'],
    ['boolean',false], ['bigint',1n], ['object',{}],
  ];
  const windowCases = [
    ['origin',0n,0n,0,0], ['lower-inclusive',95n,100n,5,0],
    ['lower-outside',94n,100n,5,0], ['upper-inclusive',105n,100n,0,5],
    ['upper-outside',106n,100n,0,5], ['u64-top',u64Max,u64Max,0,0],
    ['lower-add-overflow',u64Max,u64Max,1,0],
    ['upper-add-overflow',u64Max,u64Max-1n,0,u32Max],
    ['u32-policy-lower',0n,BigInt(u32Max),u32Max,0],
    ['u32-policy-lower-outside',0n,BigInt(u32Max)+1n,u32Max,0],
    ['exact-large-number',2 ** 53,2 ** 53,0,0],
  ];
  let passed = 0;
  function check(adapter, route, label, run) {
    try {
      run();
      passed++;
    } catch (error) {
      error.message = `${adapter}/${route}/${label}: ${error.message}`;
      throw error;
    }
  }

  for (const kind of ['node','web']) {
    const module = await import(pathToFileURL(path.join(source,`scripts/sdk/runtime_${kind}_reference.ts`)));
    const {runtime,instance} = await module.initCore({wasmBytes,manifest,secureContext:true,subtle:webcrypto.subtle});
    const scalar = instance.exports.VerifiedCore_Api_Claims_Runtime_iat_in_window;
    assert.equal(typeof scalar,'function');
    const routes = [
      {name:'claims.iat',field:'iatSeconds',bits:64,offset:48,write:fields=>runtime.writeDpopClaimsInput(fields)},
      {name:'claims.now',field:'nowUnixTimeSeconds',bits:64,offset:56,write:fields=>runtime.writeDpopClaimsInput(fields)},
      {name:'verification.now',field:'nowUnixTimeSeconds',bits:64,offset:24,write:fields=>runtime.writeDpopVerificationInput(fields)},
      {name:'parsed.iat',field:'iatSeconds',bits:64,offset:32,write:fields=>{
        const ptr=runtime.alloc(48); runtime.encodeDpopParsedComponents(ptr,fields); return ptr;
      }},
      {name:'claims.age',field:'maxAgeSeconds',bits:32,offset:64,write:fields=>runtime.writeDpopClaimsInput(fields)},
      {name:'claims.skew',field:'maxFutureSkewSeconds',bits:32,offset:68,write:fields=>runtime.writeDpopClaimsInput(fields)},
      {name:'verification.age',field:'maxAgeSeconds',bits:32,offset:32,write:fields=>runtime.writeDpopVerificationInput(fields)},
      {name:'verification.skew',field:'maxFutureSkewSeconds',bits:32,offset:36,write:fields=>runtime.writeDpopVerificationInput(fields)},
    ];
    const read = (route,ptr) => {
      const view = new DataView(runtime.memory.buffer);
      return route.bits===64 ? view.getBigUint64(ptr+route.offset,true) : view.getUint32(ptr+route.offset,true);
    };
    for (const route of routes) {
      for (const [label,value] of route.bits===64 ? validTimes : validPolicies) {
        check(kind,route.name,`stores-${label}`,()=>{
          const ptr=route.write({[route.field]:value});
          assert.equal(read(route,ptr),route.bits===64 ? BigInt(value) : value);
        });
      }
      for (const [label,value] of route.bits===64 ? invalidTimes : invalidPolicies) {
        check(kind,route.name,`rejects-${label}`,()=>{
          assert.throws(()=>route.write({[route.field]:value}),error=>error instanceof TypeError || error instanceof RangeError);
        });
      }
      if (route.name==='parsed.iat') {
        for (const [label,value] of [['undefined',undefined],['null',null]]) {
          check(kind,route.name,`requires-${label}`,()=>assert.throws(()=>route.write({iatSeconds:value}),TypeError));
        }
      } else {
        for (const [label,fields] of [['omitted',{}],['undefined',{[route.field]:undefined}],['null',{[route.field]:null}]]) {
          check(kind,route.name,`default-${label}`,()=>{
            assert.equal(read(route,route.write(fields)),route.bits===64 ? 0n : 0);
          });
        }
      }
    }
    for (const [label,iat,now,age,skew] of windowCases) {
      check(kind,'stored-claims-to-actual-window',label,()=>{
        const ptr=runtime.writeDpopClaimsInput({iatSeconds:iat,nowUnixTimeSeconds:now,maxAgeSeconds:age,maxFutureSkewSeconds:skew});
        const view=new DataView(runtime.memory.buffer);
        const stored=[view.getBigUint64(ptr+48,true),view.getBigUint64(ptr+56,true),view.getUint32(ptr+64,true),view.getUint32(ptr+68,true)];
        assert.deepEqual(stored,[BigInt(iat),BigInt(now),age,skew]);
        const expected=BigInt(iat)>=BigInt(now)-BigInt(age) && BigInt(iat)<=BigInt(now)+BigInt(skew);
        assert.equal(Boolean(scalar(...stored)),expected);
      });
    }
  }
  return passed;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const source = path.resolve(process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "../.."));
  const fixture = process.argv[3] ?? path.join(source, "tests/fixtures/verified-core/verified_core.wasm");
  const checks = await checkDpopTimePolicyBounds(source, fixture);
  console.log(`${checks} DPoP time/policy checks passed (Node and Web adapters under Node).`);
}
