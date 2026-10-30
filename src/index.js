const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const err=(message,status=400)=>json({error:message},status);
const enc=new TextEncoder();
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
async function hash(v){return hex(await crypto.subtle.digest('SHA-256',enc.encode(v)))}
const token=()=>crypto.randomUUID()+'.'+crypto.randomUUID();
async function body(req){try{return await req.json()}catch{return {}}}
async function user(req,db){const t=(req.headers.get('Authorization')||'').replace(/^Bearer /,'');if(!t)return null;return db.prepare('SELECT id,nickname FROM participants WHERE session_token_hash=?').bind(await hash(t)).first()}
const shops=db=>db.prepare('SELECT id,name,sort_order FROM shops WHERE active=1 ORDER BY sort_order,id').all();
async function state(db,u){const s=(await shops(db)).results;const rows=(await db.prepare('SELECT shop_id FROM stamps WHERE participant_id=?').bind(u.id).all()).results;const reward=await db.prepare("SELECT 1 AS redeemed FROM rewards WHERE participant_id=? AND reward_type='three'").bind(u.id).first();return {participant_id:u.id,nickname:u.nickname,shops:s,stamps:rows.map(x=>x.shop_id),sticker_redeemed:!!reward}}
async function admin(req,env){const key=req.headers.get('X-Admin-Key')||'';if(!env.ADMIN_KEY||key.length<24||key!==env.ADMIN_KEY)return err('管理者認証に失敗しました',403);return null}
export default {async fetch(req,env){
 const url=new URL(req.url),p=url.pathname,db=env.DB;
 if(p==='/api/health')return json({status:'ok',database:(await db.prepare('SELECT 1 AS ok').first())?.ok===1});
 if(!p.startsWith('/api/'))return env.ASSETS.fetch(req);
 try{
 if(p==='/api/register'&&req.method==='POST'){
  const b=await body(req),nickname=String(b.nickname||'').trim();if(!nickname||nickname.length>30)return err('ニックネームは1〜30文字で入力してください');
  const id=crypto.randomUUID(),session=token(),recovery=token();
  await db.prepare('INSERT INTO participants(id,nickname,session_token_hash,recovery_code_hash) VALUES(?,?,?,?)').bind(id,nickname,await hash(session),await hash(recovery)).run();
  return json({session,recovery,...await state(db,{id,nickname})});
 }
 if(p==='/api/recover'&&req.method==='POST'){
  const b=await body(req),code=String(b.recovery||'').trim();if(code.length<40)return err('復元コードを確認してください');
  const u=await db.prepare('SELECT id,nickname FROM participants WHERE recovery_code_hash=?').bind(await hash(code)).first();if(!u)return err('復元コードが見つかりません',404);
  const session=token();await db.prepare('UPDATE participants SET session_token_hash=? WHERE id=?').bind(await hash(session),u.id).run();
  return json({session,...await state(db,u)});
 }
 if(p==='/api/shops'&&req.method==='GET')return json({shops:(await shops(db)).results});
 if(p==='/api/admin/setup'&&req.method==='POST'){
  const e=await admin(req,env);if(e)return e;
  const b=await body(req);if(!Array.isArray(b.shops)||b.shops.length<1||b.shops.length>30)return err('店舗を1〜30件指定してください');
  for(let i=0;i<b.shops.length;i++){
   const s=b.shops[i],id=String(s.id||'').trim(),name=String(s.name||'').trim(),pin=String(s.pin||'');
   if(!/^[a-z0-9-]{1,40}$/.test(id)||!name||name.length>80||!/^[0-9]{4,8}$/.test(pin))return err('店舗ID・店舗名・暗証番号を確認してください');
   const h=await hash(env.PIN_PEPPER+':'+id+':'+pin);
   await db.prepare('INSERT INTO shops(id,name,pin_hash,sort_order,active) VALUES(?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET name=excluded.name,pin_hash=excluded.pin_hash,sort_order=excluded.sort_order,active=1').bind(id,name,h,i).run();
  }
  return json({ok:true,count:b.shops.length});
 }
 if(p==='/api/admin/stats'&&req.method==='GET'){
  const e=await admin(req,env);if(e)return e;
  const participants=(await db.prepare('SELECT COUNT(*) n FROM participants').first()).n;
  const perShop=(await db.prepare('SELECT s.id,s.name,COUNT(t.id) count FROM shops s LEFT JOIN stamps t ON s.id=t.shop_id WHERE s.active=1 GROUP BY s.id ORDER BY s.sort_order').all()).results;
  const total=perShop.length;
  const counts=(await db.prepare('SELECT participant_id,COUNT(*) n FROM stamps GROUP BY participant_id').all()).results;
  const redeemed=(await db.prepare('SELECT reward_type,COUNT(*) n FROM rewards GROUP BY reward_type').all()).results;
  return json({participants,perShop,threePlus:counts.filter(x=>x.n>=3).length,completed:counts.filter(x=>x.n>=total&&total>0).length,redeemed});
 }
 if(p==='/api/admin/redeem'&&req.method==='POST'){
  const e=await admin(req,env);if(e)return e;
  const b=await body(req),id=String(b.participant_id||''),type=String(b.reward_type||'three');
  if(!['three','all'].includes(type))return err('特典の種類が不正です');
  const n=(await db.prepare('SELECT COUNT(*) n FROM stamps WHERE participant_id=?').bind(id).first()).n;
  const total=(await db.prepare('SELECT COUNT(*) n FROM shops WHERE active=1').first()).n;
  if(!await db.prepare('SELECT 1 FROM participants WHERE id=?').bind(id).first())return err('参加者が見つかりません',404);
  if(n<(type==='three'?3:total)||!total)return err('達成条件を満たしていません');
  const result=await db.prepare('INSERT OR IGNORE INTO rewards(participant_id,reward_type) VALUES(?,?)').bind(id,type).run();return json({ok:true,already_redeemed:result.meta.changes===0});
 }
 const u=await user(req,db);if(!u)return err('参加情報が見つかりません。復元コードを利用してください',401);
 if(p==='/api/me'&&req.method==='GET')return json(await state(db,u));
 if(p==='/api/claim'&&req.method==='POST'){
  const b=await body(req),id=String(b.shop_id||''),pin=String(b.pin||'');
  if(!/^[0-9]{4,8}$/.test(pin))return err('暗証番号を確認してください');
  const now=Math.floor(Date.now()/1000),key=u.id+':'+id;
  await db.prepare('DELETE FROM pin_attempts WHERE last_attempt < ?').bind(now-86400).run();
  const attempt=await db.prepare('SELECT attempts,last_attempt FROM pin_attempts WHERE key=?').bind(key).first();
  if(attempt&&attempt.attempts>=5&&now-attempt.last_attempt<900)return err('入力回数が多いため、15分後に再試行してください',429);
  const s=await db.prepare('SELECT id,name,pin_hash FROM shops WHERE id=? AND active=1').bind(id).first();if(!s)return err('店舗が見つかりません',404);
  const existing=await db.prepare('SELECT 1 FROM stamps WHERE participant_id=? AND shop_id=?').bind(u.id,id).first();if(existing)return err('この店舗のスタンプは獲得済みです');
  if((await hash(env.PIN_PEPPER+':'+id+':'+pin))!==s.pin_hash){
   await db.prepare('INSERT INTO pin_attempts(key,attempts,last_attempt) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN last_attempt<? THEN 1 ELSE attempts+1 END,last_attempt=?').bind(key,now,now-900,now).run();return err('暗証番号が違います',403);
  }
  await db.prepare('DELETE FROM pin_attempts WHERE key=?').bind(key).run();
  await db.prepare('INSERT OR IGNORE INTO stamps(participant_id,shop_id) VALUES(?,?)').bind(u.id,id).run();return json({ok:true,...await state(db,u)});
 }
 return err('ページが見つかりません',404);
 }catch(e){console.error(e);return err('サーバーでエラーが発生しました',500)}
}};
