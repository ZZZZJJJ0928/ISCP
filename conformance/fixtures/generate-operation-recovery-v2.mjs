// Candidate-only fixture generator. Fixed public test seeds are never identities
// used by a service. Run from the repository root with Node >= 20.
import fs from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, sign, diffieHellman, hkdfSync, createCipheriv } from 'node:crypto';

const b64 = x => Buffer.from(x).toString('base64url');
const bytes = n => Buffer.alloc(n, n);
const digest = (prefix, x) => b64(createHash('sha256').update(prefix).update(canon(x)).digest());
// This is ISCP's Go-compatible JSON escaping, not ordinary JSON.stringify/JCS.
const canon = x => {
  if (Array.isArray(x)) return '[' + x.map(canon).join(',') + ']';
  if (x && typeof x === 'object') return '{' + Object.keys(x).sort().map(k => canon(k) + ':' + canon(x[k])).join(',') + '}';
  return JSON.stringify(x).replace(/[<>&\u2028\u2029]/gu, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
};
const signatureInput = (type, x) => Buffer.from('ISCP-V2-SIGNATURE\0' + type + '\0' + canon(x));
const edKey = seed => createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
const xKey = seed => createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b656e04220420','hex'),seed]),format:'der',type:'pkcs8'});
const pub = key => createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32);
const signObject = (type, object, key, kid) => ({...object, signature:{alg:'Ed25519',kid,value:b64(sign(null, signatureInput(type, object), key))}});
const ref = name => ({$ref:'#/$defs/'+name});
const object = (properties, required=Object.keys(properties)) => ({type:'object',additionalProperties:false,required,properties});
const array = (items, extra={}) => ({type:'array',items,...extra});
const str = (pattern,maxLength=160) => ({type:'string',minLength:1,maxLength,...(pattern?{pattern}:{})});
const id = str('^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$');
const hash = str('^[A-Za-z0-9_-]{43}$',43);
const counter = str('^(0|[1-9][0-9]{0,19})$',20);
const timestamp = str('^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$',20);
const protocol = {const:'iscp.operation.recovery.v2'};
const signature = object({alg:{const:'Ed25519'},kid:id,value:str('^[A-Za-z0-9_-]{86}$',86)});
const key = object({domain_id:id,device_id:id,namespace:id,operation_id:id});
const ack = object({result_digest:hash,disposition:{enum:['applied','installed','delegated','acknowledged_expired','acknowledged_superseded']},credential_generation:counter,recorded_at:timestamp,parent_result_digest:{oneOf:[hash,{type:'null'}]}});
const defs = {
  key, signature, ack,
  intent:object({
    type:{const:'iscp.operation.intent.v2'},version:{const:2},namespace:id,operation_id:id,kind:id,
    subject_binding:object({domain_id:id,device_id:id,binding_id:id}),
    target:object({service_id:id,resource_id:id}),
    task_authorization:{oneOf:[
      object({kind:{const:'standing'},authorization_revision:counter,scopes:array(id,{uniqueItems:true,minItems:1,maxItems:256})}),
      object({kind:{const:'task'},grant:{type:'object'},approval_digests:array(hash,{uniqueItems:true,maxItems:256})})
    ]},
    payload:{type:'object',description:'The registered operation-family schema MUST reject unknown fields.'},
    business_deadline:{oneOf:[timestamp,{type:'null'}]},
    preconditions:object({resource_version:counter,credential_generation:counter,authorization_revision:counter}),
    parent:object({key:ref('key'),semantic_digest:hash,step:id,child_index:counter}),
    predecessor:object({key:ref('key'),result_digest:hash,disposition_digest:hash})
  },['type','version','namespace','operation_id','kind','subject_binding','target','task_authorization','payload','business_deadline','preconditions']),
  challenge_request:object({type:{const:'iscp.control.challenge.request.v2'},protocol,audience:id,domain_id:id,device_id:id,purpose:{enum:['submit','lookup','recover','ack']}}),
  challenge:object({type:{const:'iscp.control.challenge.v2'},protocol,audience:id,challenge_id:hash,challenge:hash,purpose:{enum:['submit','lookup','recover','ack']},server_time:timestamp,expires_at:timestamp}),
  authentication:object({challenge_id:hash,challenge:hash,nonce:str('^[A-Za-z0-9_-]{22,86}$',86),issued_at:timestamp,signature:ref('signature')}),
  delivery:object({delivery_id:hash,recipient_public_key:hash}),
  authentication_context:object({type:{const:'iscp.control.authentication.v2'},protocol,purpose:{enum:['submit','lookup','recover','ack']},method:{const:'POST'},path:{enum:['/v2/control/operations/submit','/v2/control/operations/lookup','/v2/control/operations/recover','/v2/control/operations/ack']},audience:id,domain_id:id,device_id:id,challenge_id:hash,challenge:hash,nonce:str('^[A-Za-z0-9_-]{22,86}$',86),issued_at:timestamp,request_digest:hash,credential_sha256:{oneOf:[hash,{type:'null'}]}}),
  result_payload:object({type:{const:'iscp.operation.result.payload.v2'},protocol,key:ref('key'),semantic_digest:hash,result_version:counter,state:{enum:['succeeded','failed','cancelled']},completed_at:timestamp,credential_generation:counter,body:{type:'object'}}),
  result:object({type:{const:'iscp.operation.result.v2'},payload:ref('result_payload'),result_digest:hash,signature:ref('signature')}),
  status:object({type:{const:'iscp.operation.status.v2'},protocol,attempt_id:id,key:ref('key'),semantic_digest:hash,state:{enum:['admitted','running','succeeded','failed','cancelled','absent','unknown','conflict','namespace_closed']},record_version:counter,history_id:hash,history_complete:{type:'boolean'},code:{enum:['none','history_unavailable','commit_unknown','effect_unknown','result_expired','operation_conflict','namespace_closed']},result_digest:{oneOf:[hash,{type:'null'}]},credential_generation:counter,checked_at:timestamp,signature:ref('signature')}),
  error:object({type:{const:'iscp.operation.error.v2'},protocol,attempt_id:id,audience:id,code:{enum:['invalid_request','protocol_incompatible','challenge_expired','authentication_failed','authorization_unavailable','authorization_revoked','authorization_ended','identity_recovery_required','scope_denied','generation_conflict','deadline_exceeded','resource_exhausted']},retryable:{type:'boolean'},server_time:timestamp,signature:ref('signature')}),
  disposition_receipt:object({type:{const:'iscp.operation.disposition.v2'},protocol,key:ref('key'),semantic_digest:hash,ack:ref('ack'),disposition_digest:hash,accepted_at:timestamp,signature:ref('signature')}),
  sealed_result:object({type:{const:'iscp.operation.sealed-result.v2'},protocol,attempt_id:id,key:ref('key'),semantic_digest:hash,result_digest:hash,delivery_id:hash,recipient_public_key:hash,server_public_key:hash,nonce:str('^[A-Za-z0-9_-]{16}$',16),ciphertext:str('^[A-Za-z0-9_-]+$',1048576),ciphersuite:{const:'ISCP_V2_X25519_HKDF_SHA256_CHACHA20POLY1305'}})
};
// Only these control profiles are frozen. Existing application schemas retain
// their own task authorization, payload and result contracts.
defs.intent.properties.namespace={enum:['control.credentials.v2','control.relay-credentials.v2']};
defs.intent.properties.kind={enum:['credential.renew','credential.recover','relay.refresh','relay.recover']};
defs.intent.properties.task_authorization=object({kind:{const:'standing'},authorization_revision:counter,scopes:array(id,{uniqueItems:true,minItems:1,maxItems:256})});
defs.intent.properties.payload=object({requested_scopes:array(id,{uniqueItems:true,minItems:1,maxItems:256})});
defs.intent.properties.business_deadline={type:'null'};
defs.relay_credential=object({domain_id:id,device_id:id,token:str(null,4096),expires_at:timestamp});
defs.relay_credentials=object({target_service_id:id,binding_id:id,credential_generation:counter,authorization_revision:counter,access:ref('relay_credential'),refresh:ref('relay_credential')});
defs.trust_grant=object({type:{const:'iscp.trust_grant.v2'},grant_id:id,issuer:id,subject_device_id:id,audience:id,confirmation_thumbprint:hash,permissions:array(id,{uniqueItems:true,minItems:1,maxItems:256}),relay_constraints:array(id,{uniqueItems:true,maxItems:256}),not_before:timestamp,expires_at:timestamp,revocation_epoch:{type:'integer',minimum:0,maximum:9007199254740991},signature:ref('signature')},['type','grant_id','issuer','subject_device_id','audience','confirmation_thumbprint','permissions','not_before','expires_at','revocation_epoch','signature']);
defs.relay_result_payload=object({...defs.result_payload.properties,body:object({relay_credentials:ref('relay_credentials')})});
defs.relay_result=object({...defs.result.properties,payload:ref('relay_result_payload')});
defs.result_payload.properties.body={oneOf:[object({grant:ref('trust_grant')}),object({grant:ref('trust_grant'),relay_result:ref('relay_result')}),object({relay_credentials:ref('relay_credentials')}),object({code:{enum:['scope_denied','generation_conflict','authorization_revoked','authorization_ended','cancelled']}})]};
const statusBase=defs.status.properties;
const statusVariant=(state,code,complete,resultDigest,extra={})=>object({...statusBase,state:{const:state},code:{const:code},history_complete:{const:complete},result_digest:resultDigest,...extra});
defs.status={oneOf:[
  ...['admitted','running'].map(s=>statusVariant(s,'none',true,{type:'null'})),
  ...['succeeded','failed','cancelled'].flatMap(s=>['none','result_expired'].map(code=>statusVariant(s,code,true,hash))),
  statusVariant('absent','none',true,{type:'null'},{record_version:{const:'0'}}),
  statusVariant('unknown','history_unavailable',false,{type:'null'}),
  ...['commit_unknown','effect_unknown'].map(code=>statusVariant('unknown',code,true,{type:'null'})),
  statusVariant('conflict','operation_conflict',true,{type:'null'}),
  statusVariant('namespace_closed','namespace_closed',false,{type:'null'})
]};
const errorBase={...defs.error.properties,attempt_id:{oneOf:[id,{type:'null'}]},key:{oneOf:[ref('key'),{type:'null'}]},authorization_revision:{oneOf:[counter,{type:'null'}]}};
const retryableErrors=new Set(['challenge_expired','authorization_unavailable','resource_exhausted']);
defs.error={oneOf:defs.error.properties.code.enum.map(code=>object({...errorBase,code:{const:code},retryable:{const:retryableErrors.has(code)},...(['authorization_revoked','authorization_ended'].includes(code)?{key:ref('key'),authorization_revision:counter,attempt_id:id}:{})}))};
const common={type:{const:'iscp.operation.request.v2'},protocol,attempt_id:id,action:{},key:ref('key'),semantic_digest:hash,authentication:ref('authentication')};
for(const action of ['submit','recover','lookup','ack']){
  const properties={...common,action:{const:action},...(action==='submit'||action==='recover'?{intent:ref('intent')}:{}),...(action==='ack'?{ack:ref('ack')}:{delivery:ref('delivery')})};
  defs['request_'+action]=object(properties);
}
const schema={$schema:'https://json-schema.org/draft/2020-12/schema',$id:'https://schemas.iscp.dev/candidates/operation-recovery.v2.json',title:'0041 authentication/operation recovery freeze candidate',description:'Candidate only, not an advertised protocol. Before schema validation reject malformed UTF-8, duplicate members, lone surrogates, trailing garbage, non-integer JSON numbers; enforce all semantic and cryptographic checks in the accompanying spec.',oneOf:Object.keys(defs).filter(k=>!['key','signature','ack','authentication','delivery','relay_credential','relay_credentials','trust_grant','relay_result','relay_result_payload'].includes(k)).map(ref),$defs:defs};
fs.mkdirSync('schemas/candidates',{recursive:true});
fs.writeFileSync('schemas/candidates/operation-recovery.v2.json',JSON.stringify(schema,null,2)+'\n');

const issuer=edKey(Buffer.alloc(32,1)), device=edKey(Buffer.alloc(32,2)), relaySigner=edKey(Buffer.alloc(32,15));
const intent={type:'iscp.operation.intent.v2',version:2,namespace:'control.credentials.v2',operation_id:'renew-fixture-1',kind:'credential.renew',subject_binding:{domain_id:'domain-test',device_id:'device-test',binding_id:'binding-test'},target:{service_id:'issuer-test',resource_id:'binding-test'},task_authorization:{kind:'standing',authorization_revision:'7',scopes:['connect','workbench']},payload:{requested_scopes:['connect','workbench']},business_deadline:null,preconditions:{resource_version:'3',credential_generation:'8',authorization_revision:'7'}};
const semanticDigest=digest('ISCP-OPERATION-INTENT-V2\0',intent);
const opKey={domain_id:'domain-test',device_id:'device-test',namespace:intent.namespace,operation_id:intent.operation_id};
const clientKey=xKey(Buffer.alloc(32,3));
const challenge={type:'iscp.control.challenge.v2',protocol:protocol.const,audience:'issuer-test',challenge_id:b64(Buffer.alloc(32,4)),challenge:b64(Buffer.alloc(32,5)),purpose:'recover',server_time:'2026-10-19T04:00:00Z',expires_at:'2026-10-19T04:00:10Z'};
const authentication={challenge_id:challenge.challenge_id,challenge:challenge.challenge,nonce:b64(Buffer.alloc(24,6)),issued_at:challenge.server_time};
const unsignedRequest={type:'iscp.operation.request.v2',protocol:protocol.const,attempt_id:'attempt-fixture-1',action:'recover',key:opKey,semantic_digest:semanticDigest,intent,delivery:{delivery_id:b64(Buffer.alloc(32,7)),recipient_public_key:b64(pub(clientKey))}};
const context={type:'iscp.control.authentication.v2',protocol:protocol.const,purpose:'recover',method:'POST',path:'/v2/control/operations/recover',audience:'issuer-test',domain_id:'domain-test',device_id:'device-test',...authentication,request_digest:digest('ISCP-CONTROL-REQUEST-V2\0',unsignedRequest),credential_sha256:null};
const request={...unsignedRequest,authentication:{...authentication,signature:{alg:'Ed25519',kid:'device-key-test',value:b64(sign(null,signatureInput(context.type,context),device))}}};
const grant=signObject('iscp.trust_grant.v2',{type:'iscp.trust_grant.v2',grant_id:'grant-fixture-9',issuer:'issuer-test',subject_device_id:'device-test',audience:'gateway-test',confirmation_thumbprint:b64(createHash('sha256').update('iscp/v2/thumbprint/Ed25519\0').update(pub(device)).digest()),permissions:['connect','workbench'],not_before:'2026-10-19T04:00:01Z',expires_at:'2026-10-19T04:30:01Z',revocation_epoch:7},issuer,'issuer-key-test');
const resultPayload={type:'iscp.operation.result.payload.v2',protocol:protocol.const,key:opKey,semantic_digest:semanticDigest,result_version:'1',state:'succeeded',completed_at:'2026-10-19T04:00:01Z',credential_generation:'9',body:{grant}};
const resultDigest=digest('ISCP-OPERATION-RESULT-V2\0',resultPayload);
const result=signObject('iscp.operation.result.v2',{type:'iscp.operation.result.v2',payload:resultPayload,result_digest:resultDigest},issuer,'issuer-key-test');
const expiredAck={result_digest:resultDigest,disposition:'acknowledged_expired',credential_generation:'9',recorded_at:'2026-10-21T04:00:00Z',parent_result_digest:null};
const dispositionBase={type:'iscp.operation.disposition.v2',protocol:protocol.const,key:opKey,semantic_digest:semanticDigest,ack:expiredAck};
const disposition=signObject(dispositionBase.type,{...dispositionBase,disposition_digest:digest('ISCP-OPERATION-DISPOSITION-V2\0',dispositionBase),accepted_at:'2026-10-21T04:00:01Z'},issuer,'issuer-key-test');
function sealedResult(clientSeed,serverSeed,nonceByte,deliveryByte){
  const client=xKey(Buffer.alloc(32,clientSeed)),server=xKey(Buffer.alloc(32,serverSeed));
  const deliveryContext={protocol:protocol.const,key:opKey,semantic_digest:semanticDigest,result_digest:resultDigest,delivery_id:b64(Buffer.alloc(32,deliveryByte)),recipient_public_key:b64(pub(client)),server_public_key:b64(pub(server))};
  const salt=createHash('sha256').update('ISCP-CONTROL-RESULT-SALT-V2\0').update(canon(deliveryContext)).digest();
  const info=Buffer.from('ISCP-CONTROL-RESULT-KEY-V2\0'+canon(deliveryContext));
  const aad=Buffer.from('ISCP-CONTROL-RESULT-AAD-V2\0'+canon(deliveryContext));
  const secret=diffieHellman({privateKey:server,publicKey:createPublicKey(client)});
  const key=Buffer.from(hkdfSync('sha256',secret,salt,info,32));
  const nonce=Buffer.alloc(12,nonceByte),cipher=createCipheriv('chacha20-poly1305',key,nonce,{authTagLength:16});
  cipher.setAAD(aad);
  const ciphertext=Buffer.concat([cipher.update(canon(result)),cipher.final(),cipher.getAuthTag()]);
  return {client_seed_hex:Buffer.alloc(32,clientSeed).toString('hex'),server_seed_hex:Buffer.alloc(32,serverSeed).toString('hex'),context:deliveryContext,context_canonical:canon(deliveryContext),salt_hex:salt.toString('hex'),key_hex:key.toString('hex'),aad_hex:aad.toString('hex'),wire:{type:'iscp.operation.sealed-result.v2',attempt_id:'attempt-fixture-'+deliveryByte,...deliveryContext,nonce:b64(nonce),ciphertext:b64(ciphertext),ciphersuite:'ISCP_V2_X25519_HKDF_SHA256_CHACHA20POLY1305'}};
}
const childContext={parent_key:opKey,parent_semantic_digest:semanticDigest,target_service_id:'relay-test',step:'relay.credentials.recover',child_index:'0',predecessor_disposition_digest:null};
const childID='child-'+digest('ISCP-CHILD-OPERATION-V2\0',childContext);
const mutation=(name,path,value)=>({name,path,value});
const fixture={status:'candidate',protocol:protocol.const,test_keys:{issuer_seed_hex:Buffer.alloc(32,1).toString('hex'),issuer_public_key:b64(pub(issuer)),device_seed_hex:Buffer.alloc(32,2).toString('hex'),device_public_key:b64(pub(device))},intent,intent_canonical:canon(intent),semantic_digest:semanticDigest,challenge,request,authentication_context:context,authentication_context_canonical:canon(context),authentication_signature_input_hex:signatureInput(context.type,context).toString('hex'),result,result_payload_canonical:canon(resultPayload),result_digest:resultDigest,disposition,child:{context:childContext,canonical:canon(childContext),operation_id:childID},deliveries:[sealedResult(3,8,9,7),sealedResult(10,11,12,13)],negative_raw:[
  {name:'duplicate-member',raw:'{"type":"x","type":"y"}'},
  {name:'trailing-garbage',raw:canon(intent)+' garbage'},
  {name:'lone-surrogate',raw:'{"value":"\\ud800"}'},
  {name:'float',raw:'{"version":2.0}'},
  {name:'exponent',raw:'{"version":2e0}'},
  {name:'invalid-utf8',raw_hex:'7b2278223a22ff227d'}
],negative_schema:[
  mutation('proof-in-intent',['intent','proof'],{}),
  mutation('unknown-envelope-field',['unknown'],true),
  mutation('numeric-generation',['intent','preconditions','credential_generation'],8),
  mutation('leading-zero-generation',['intent','preconditions','credential_generation'],'08'),
  mutation('unknown-proof-field',['authentication','authority'],true),
  mutation('wrong-version',['intent','version'],1),
  mutation('invalid-wrap-key',['delivery','recipient_public_key'],'bad='),
  mutation('duplicate-scope',['intent','task_authorization','scopes'],['connect','connect']),
  mutation('fractional-time',['authentication','issued_at'],'2026-10-19T04:00:00.001Z')
],negative_binding:[
  mutation('wrong-audience',['audience'],'other-issuer'),
  mutation('wrong-method',['method'],'GET'),
  mutation('wrong-path',['path'],'/v2/control/operations/submit'),
  mutation('wrong-purpose',['purpose'],'submit'),
  mutation('wrong-challenge',['challenge'],b64(Buffer.alloc(32,99))),
  mutation('wrong-request',['request_digest'],b64(Buffer.alloc(32,99))),
  mutation('wrong-credential',['credential_sha256'],b64(Buffer.alloc(32,99)))
]};
fixture.status_record=signObject('iscp.operation.status.v2',{type:'iscp.operation.status.v2',protocol:protocol.const,attempt_id:'attempt-fixture-1',key:opKey,semantic_digest:semanticDigest,state:'succeeded',record_version:'2',history_id:b64(Buffer.alloc(32,14)),history_complete:true,code:'none',result_digest:resultDigest,credential_generation:'9',checked_at:'2026-10-21T04:00:00Z'},issuer,'issuer-key-test');
fixture.families=[
  {namespace:'control.credentials.v2',kinds:['credential.renew','credential.recover'],recovery:'find_or_admit',owner:'issuer'},
  {namespace:'control.relay-credentials.v2',kinds:['relay.refresh','relay.recover'],recovery:'find_or_admit',owner:'relay'},
  {namespace:'sparkclaw.execution.existing',kinds:['execution.submit'],recovery:'lookup_only',owner:'SparkClaw'},
  {namespace:'sparkclaw.domain.existing',kinds:['existing operation_receipt families'],recovery:'lookup_only',owner:'SparkClaw'},
  {namespace:'jingsi.runtime.v1',kinds:['submit'],recovery:'lookup_with_permanent_not_started_fence',owner:'accepted external contract'}
];
const delegatedParentIntent={...intent,kind:'credential.recover',operation_id:'recover-fixture-1'};
const delegatedParentDigest=digest('ISCP-OPERATION-INTENT-V2\0',delegatedParentIntent);
const delegatedParentKey={...opKey,operation_id:delegatedParentIntent.operation_id};
const delegatedChildContext={...childContext,parent_key:delegatedParentKey,parent_semantic_digest:delegatedParentDigest};
const delegatedChildID='child-'+digest('ISCP-CHILD-OPERATION-V2\0',delegatedChildContext);
fixture.child={context:delegatedChildContext,canonical:canon(delegatedChildContext),operation_id:delegatedChildID};
fixture.parent_recovery_intent=delegatedParentIntent;
const childIntent={...intent,namespace:'control.relay-credentials.v2',operation_id:delegatedChildID,kind:'relay.recover',target:{service_id:'relay-test',resource_id:'binding-test'},preconditions:{...intent.preconditions,credential_generation:'21'},parent:{key:delegatedParentKey,semantic_digest:delegatedParentDigest,step:'relay.credentials.recover',child_index:'0'}};
fixture.delegated_child={authenticated_actor:{domain_id:'domain-test',device_id:'issuer-service-test'},key:{domain_id:'domain-test',device_id:'issuer-service-test',namespace:childIntent.namespace,operation_id:delegatedChildID},intent:childIntent,semantic_digest:digest('ISCP-OPERATION-INTENT-V2\0',childIntent),stored_authority:{domain_id:'domain-test',device_id:'device-test',binding_id:'binding-test',issuer_device_id:'issuer-service-test',service_active:true,subject_active:true,authorization_revision:'7',resource_version:'3',credential_generation:'21',scopes:['connect','workbench']}};
const childResultPayload={...resultPayload,key:fixture.delegated_child.key,semantic_digest:fixture.delegated_child.semantic_digest,credential_generation:'22',body:{relay_credentials:{target_service_id:'relay-test',binding_id:'binding-test',credential_generation:'22',authorization_revision:'7',access:{domain_id:'domain-test',device_id:'device-test',token:'PUBLIC-CHILD-ACCESS-NOT-A-CREDENTIAL',expires_at:'2026-10-19T04:30:01Z'},refresh:{domain_id:'domain-test',device_id:'device-test',token:'PUBLIC-CHILD-REFRESH-NOT-A-CREDENTIAL',expires_at:'2026-10-20T04:00:01Z'}}}};
const childResultDigest=digest('ISCP-OPERATION-RESULT-V2\0',childResultPayload);
fixture.test_keys.relay_public_key=b64(pub(relaySigner));
fixture.child_result=signObject('iscp.operation.result.v2',{type:'iscp.operation.result.v2',payload:childResultPayload,result_digest:childResultDigest},relaySigner,'relay-key-test');
const childDispositionBase={...dispositionBase,key:fixture.delegated_child.key,semantic_digest:fixture.delegated_child.semantic_digest,ack:{...expiredAck,result_digest:childResultDigest,credential_generation:'22'}};
fixture.child_disposition=signObject(childDispositionBase.type,{...childDispositionBase,disposition_digest:digest('ISCP-OPERATION-DISPOSITION-V2\0',childDispositionBase),accepted_at:'2026-10-21T04:00:01Z'},relaySigner,'relay-key-test');
const successorContext={...delegatedChildContext,child_index:'1',predecessor_disposition_digest:fixture.child_disposition.disposition_digest};
fixture.child_successor={context:successorContext,operation_id:'child-'+digest('ISCP-CHILD-OPERATION-V2\0',successorContext),expected_credential_generation:'22',predecessor:{key:fixture.delegated_child.key,result_digest:childResultDigest,disposition_digest:fixture.child_disposition.disposition_digest},requires_predecessor_closed:true};
const parentRecoveryPayload={...resultPayload,key:delegatedParentKey,semantic_digest:delegatedParentDigest,body:{grant,relay_result:fixture.child_result}};
const parentRecoveryDigest=digest('ISCP-OPERATION-RESULT-V2\0',parentRecoveryPayload);
fixture.parent_recovery_result=signObject('iscp.operation.result.v2',{type:'iscp.operation.result.v2',payload:parentRecoveryPayload,result_digest:parentRecoveryDigest},issuer,'issuer-key-test');
const delegatedDispositionBase={...childDispositionBase,ack:{...childDispositionBase.ack,disposition:'delegated',recorded_at:'2026-10-19T04:00:03Z',parent_result_digest:parentRecoveryDigest}};
fixture.child_delegated_disposition=signObject(delegatedDispositionBase.type,{...delegatedDispositionBase,disposition_digest:digest('ISCP-OPERATION-DISPOSITION-V2\0',delegatedDispositionBase),accepted_at:'2026-10-19T04:00:04Z'},relaySigner,'relay-key-test');
fixture.scenario_note='child_disposition/child_successor and parent_recovery_result/child_delegated_disposition are alternative histories, never conflicting dispositions in one ledger';
fixture.negative_status=[mutation('missing-history-cannot-succeed',['history_complete'],false),mutation('terminal-without-result-digest',['result_digest'],null),mutation('terminal-marked-history-unknown',['code'],'history_unavailable'),mutation('absence-with-terminal-result',['state'],'absent')];
fixture.negative_delegation=[
  mutation('wrong-service-actor',['authenticated_actor','device_id'],'unrelated-service'),
  mutation('wrong-target-subject',['intent','subject_binding','device_id'],'another-device'),
  mutation('wrong-binding',['intent','subject_binding','binding_id'],'another-binding'),
  mutation('scope-escalation',['intent','payload','requested_scopes'],['admin']),
  mutation('target-revoked',['stored_authority','subject_active'],false),
  mutation('issuer-revoked',['stored_authority','service_active'],false),
  mutation('revision-stale',['intent','preconditions','authorization_revision'],'6'),
  mutation('wrong-parent-subject',['intent','parent','key','device_id'],'another-device'),
  mutation('wrong-child-key',['key','operation_id'],'another-child')
];
fs.writeFileSync('conformance/fixtures/operation-recovery.v2.json',JSON.stringify(fixture,null,2)+'\n');
