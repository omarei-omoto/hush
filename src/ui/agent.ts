/**
 * The Agent and Activity sections.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const AGENT = String.raw`/* ------------------------------------------------------------------ agent */

function copyCmd(text){
  return h("span",{class:"cmd"},h("code",{text:text}),h("button",{type:"button",class:"iconbtn","aria-label":"Copy "+text,onclick:async function(){
    try{await navigator.clipboard.writeText(text);toast("copied")}catch(e){toast("copying is blocked here",{error:true})}}},icon("copy")));
}

function renderAgent(page){
  page.append(h("header",{class:"head"},h("div",null,h("h1",null,"Agent"),
    h("p",{text:"Your coding agent can use these secrets without ever reading one. Here's what it's connected to, and what it has to ask you first."}))));

  const steps=[
    {ok:S.agent.mcpRegistered,t:"Connect hush to your agent",d:"Adds hush's tools to Claude Code, Codex or Cursor — it asks before writing each file.",cmd:"hush install-mcp"},
    {ok:S.agent.skillInstalled,t:"Teach it the rules",d:"A short skill: never ask for a key in chat, pick the right set, open the secure prompt instead.",cmd:"hush install-skill"},
    {ok:S.agent.policyFloorPresent,t:"Optional: a floor this repo can't lower",d:"Rules in ~/.hush/policy.json that apply to every project, whatever its own file says.",cmd:"hush secure"},
  ];
  const list=h("div",{class:"card list"});
  steps.forEach(function(s){
    list.append(h("div",{class:"li",style:"align-items:flex-start"},h("div",{class:"stepicon"+(s.ok?" ok":"")},s.ok?icon("check"):null),
      h("div",{class:"body"},h("div",{class:"t",text:s.t}),h("div",{class:"d",text:s.ok?"Done.":s.d}),s.ok?null:copyCmd(s.cmd))));
  });
  page.append(list);

  const ACTIONS=[
    ["run","Running a command with secrets","hush run, hush dev, and the agent's hush_run. The prompt names the command and the keys."],
    ["request","Sending a secret to an API","hush request and the agent's hush_request."],
    ["reveal","Showing a value","hush get, hush export, and Reveal on this page."],
    ["add","Saving a new secret","So nothing lands in the vault that you didn't see."],
  ];
  const sw=h("div",{class:"card list"});
  ACTIONS.forEach(function(a){
    const cb=h("input",{type:"checkbox",checked:S.policy.requireApproval.indexOf(a[0])>-1,"aria-label":"Ask first: "+a[1]});
    cb.onchange=async function(){
      const next=new Set(S.policy.requireApproval);
      if(cb.checked)next.add(a[0]);else next.delete(a[0]);
      try{S=await api("/api/policy",{requireApproval:Array.from(next)});render();toast(cb.checked?"asks first now":"no longer asks")}
      catch(e){cb.checked=!cb.checked}
    };
    sw.append(h("label",{class:"li",style:"cursor:pointer"},h("div",{class:"body"},h("div",{class:"t",text:a[1]}),h("div",{class:"d",text:a[2]})),
      h("span",{class:"switch"},cb,h("i"))));
  });
  const TTL=[[900,"15 minutes"],[1800,"30 minutes"],[3600,"1 hour"],[14400,"4 hours"],[86400,"all day"]];
  const ttl=h("select",{class:"input",style:"width:auto","aria-label":"How long an Allow lasts"});
  TTL.forEach(function(p){ttl.append(h("option",{value:String(p[0])},p[1]))});
  if(!TTL.some(function(p){return p[0]===S.policy.approvalTtlSeconds})){
    ttl.append(h("option",{value:String(S.policy.approvalTtlSeconds)},Math.round(S.policy.approvalTtlSeconds/60)+" minutes (set by hand)"));
  }
  ttl.value=String(S.policy.approvalTtlSeconds);
  ttl.onchange=async function(){
    try{S=await api("/api/policy",{requireApproval:S.policy.requireApproval,approvalTtlSeconds:Number(ttl.value)});render();toast("saved")}catch(e){}
  };
  sw.append(h("div",{class:"li"},h("div",{class:"body"},h("div",{class:"t"},"An “Allow” lasts"),
    h("div",{class:"d",text:"For your agent's session. A command in your terminal always asks once."})),ttl));

  const how=S.policy.promptAvailable
    ?(S.policy.biometryAvailable&&S.policy.biometry!=="off"?"Prompts use your fingerprint.":"Prompts appear as a dialog on this screen, with a code that also shows in the agent's transcript.")
    :null;
  page.append(h("section",{class:"section"},h("div",{class:"sechead"},h("div",null,h("h2",null,"Ask me first before…"),
    h("p",{text:"Written to .hush/policy.json, so the team gets the same rules. In your own terminal nothing is blocked outright — risky commands just say so in the prompt."}))),
    S.policy.promptAvailable?null:h("div",{class:"banner warn",style:"margin-bottom:12px"},icon("alert"),h("span",{text:"Nothing on this machine can show a prompt (no desktop dialog or fingerprint reader), so anything switched on below is refused."})),
    sw,how?h("p",{class:"muted",style:"font-size:13px;margin:10px 2px 0",text:how}):null));

  const p=S.posture;
  const meter=h("div",{class:"meter",style:"margin:10px 0 12px"});
  for(let i=1;i<=5;i++)meter.append(h("i",{class:i<=p.rung?"on":""}));
  page.append(h("section",{class:"card pad section","aria-label":"Security level"},
    h("div",{class:"sechead",style:"margin:0"},h("div",null,h("h3",null,"How protected this is"),h("p",{class:"lead",text:"Level "+p.rung+" of 5 · "+p.name})),
      p.rung>=5?h("span",{class:"badge ok"},icon("check"),"top level"):null),
    meter,
    p.next?h("div",null,h("div",{style:"font-weight:600"},"Next: "+p.next.label),p.next.why?h("div",{class:"muted",text:p.next.why}):null,
      /^hush /.test(p.next.command)?copyCmd(p.next.command):h("div",{class:"muted mono",style:"font-size:12.5px;margin-top:4px",text:p.next.command})):null));
}

/* --------------------------------------------------------------- activity */

const WHO={cli:"terminal",mcp:"agent",ui:"this app"};
/** A set's name as the person gave it, when the log only has its slug. */
function nm(slug){
  if(!slug||!S)return slug||"";
  const x=S.project.find(function(s){return s.name===slug})||S.library.find(function(s){return s.name===slug});
  return x?x.label:slug;
}
function describeEvent(e){
  const k=e.key||"",set=nm(e.env||e.set||e.scope||"");
  const list=function(v){return Array.isArray(v)?v.join(", "):String(v||"")};
  switch(e.action){
    case "add":
      if(e.kind==="start"||e.file)return ["change","Imported "+plural(Number(e.added)||0,"key")+" from "+(e.file||"a file")+(set?" into "+set:"")];
      if(e.actor==="mcp")return ["change","Agent had you add "+(list(e.stored)||"a secret")+(set?" to "+set:"")];
      return ["change","Added "+(k||list(e.keys)||"a secret")+(set?" to "+set:"")];
    case "set":case "create":return ["change","Saved "+k+(set?" in "+set:"")];
    case "update":return ["change","Changed "+k+(set?" in "+set:"")];
    case "delete":return ["change","Deleted "+k+(set?" from "+set:"")];
    case "add.cancelled":return ["other","You cancelled adding "+list(e.vars)];
    case "reveal":return ["read","Revealed "+(k||"a value")+(String(e.to||"").indexOf("clipboard")===0?" to the clipboard":"")];
    case "export":return ["read","Exported secrets to "+(e.to||"stdout")];
    case "run":return ["use","Ran "+(e.command||"a command")+(e.injected!==undefined?" with "+plural(Number(e.injected),"secret"):"")+(e.exit!==undefined&&e.exit!==0?" · exit "+e.exit:"")];
    case "request":return ["use",(e.method||"Called")+" "+(e.url?String(e.url).replace(/^https?:\/\//,"").split(/[/?]/)[0]:"an API")+(e.status?" · "+e.status:"")];
    case "approval":{
      const d=e.decision==="deny"?"Denied":e.decision==="timeout"?"Nobody answered":"Approved";
      return [e.decision==="deny"||e.decision==="timeout"?"deny":"use",d+" "+(e.on==="run"?"a run":e.on==="request"?"an API call":e.on==="reveal"?"a reveal":e.on==="materialize"?"writing a secret to disk":(e.on||"a request"))+(e.via==="none"&&e.decision==="deny"?" — no prompt available":"")];
    }
    case "import":return ["change","Imported "+plural(Number(e.imported)||0,"key")+(e.skipped?", skipped "+e.skipped:"")];
    case "stage":return ["other","Opened "+(e.file||"a file")+" for review ("+plural(Number(e.keys)||0,"key")+")"];
    case "discard":return ["other","Discarded a dropped file"];
    case "tag":return ["change",(e.tagged?"Tagged ":"Cleared the tag on ")+k];
    case "move":return ["change","Moved "+k+" from "+nm(e.from)+" to "+nm(e.to)];
    case "env.create":return ["change","Created the set "+nm(e.name)];
    case "env.rename":return ["change","Renamed "+e.from+" to "+nm(e.to)];
    case "env.describe":return ["change","Edited the details of "+nm(e.name)];
    case "env.delete":case "rm.set":return ["change","Deleted the set "+(e.name||e.set||"")];
    case "env.order":return ["change","Changed the order sets apply in"];
    case "env.use":return ["change","Started using "+nm(e.name)+" here"];
    case "env.drop":return ["change","Stopped using "+nm(e.name)+" here"];
    case "team.add":return ["change","Gave "+(e.name||"someone")+" access"];
    case "team.remove":return ["change","Removed "+(e.name||"someone")];
    case "policy.update":return ["change","Changed what asks first"];
    case "setup":return ["change","Set up this folder"];
    case "global.create":return ["change","Created your library"];
    case "global.adopt":return ["change","Switched your library to "+(e.name||"")];
    case "verify":return ["other","Checked the vault"];
    case "rotate":return ["change","Rotated the vault key"];
    case "list":return ["other","Agent listed the secrets in "+(set||"a set")];
    case "describe":return ["other","Agent looked up "+(k||"a secret")];
    case "check":return ["other","Agent checked what the code needs"+(e.missing?" · "+e.missing+" missing":"")];
    case "provision":return ["other","Agent prepared "+(e.tool||e.service||"a tool")];
  }
  const parts=[];
  Object.keys(e).forEach(function(x){if(x==="at"||x==="actor"||x==="action")return;const v=e[x];if(v===undefined||v===null||v==="")return;parts.push(x+": "+list(v))});
  return ["other",(e.action||"event")+(parts.length?" — "+parts.join(", "):"")];
}
function relTime(iso){
  const t=new Date(iso).getTime();if(isNaN(t))return "";
  const s=Math.max(0,Math.round((Date.now()-t)/1000));
  if(s<60)return "just now";
  const m=Math.round(s/60);if(m<60)return m+" min ago";
  const hr=Math.round(m/60);if(hr<24)return hr+" h ago";
  return new Date(t).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
}
function dayLabel(iso){
  const d=new Date(iso);if(isNaN(d.getTime()))return "Earlier";
  const today=new Date();today.setHours(0,0,0,0);
  const that=new Date(d);that.setHours(0,0,0,0);
  const diff=Math.round((today-that)/86400000);
  return diff===0?"Today":diff===1?"Yesterday":d.toLocaleDateString([],{weekday:"long",month:"short",day:"numeric"});
}
let AUDIT=null;
let auditLoading=false;
async function loadAudit(){
  if(auditLoading)return;auditLoading=true;
  try{AUDIT=(await api("/api/audit",{})).entries||[]}catch(e){AUDIT=[]}
  finally{auditLoading=false}
  if(route()==="activity")render();
}
function renderActivity(page){
  page.append(h("header",{class:"head"},h("div",null,h("h1",null,"Activity"),
    h("p",{text:"What was done with this project's secrets, by you, your terminal and your agent. Values are never logged."})),
    h("div",{class:"actions"},h("button",{type:"button",class:"btn",onclick:function(){AUDIT=null;render();loadAudit()}},"Refresh"))));
  if(AUDIT===null){page.append(h("p",{class:"muted",text:"Loading…"}));loadAudit();return}
  if(!AUDIT.length){page.append(h("div",{class:"card"},h("div",{class:"empty"},h("h3",null,"Nothing yet"),h("p",null,"Runs, reveals and changes show up here."))));return}
  let day=null,box=null;
  AUDIT.forEach(function(e){
    const dl=dayLabel(e.at);
    if(dl!==day){day=dl;page.append(h("div",{class:"day",text:dl}));box=h("div",{class:"card"});page.append(box)}
    const d=describeEvent(e);
    box.append(h("div",{class:"ev"},h("span",{class:"kind "+d[0]}),
      h("div",null,h("span",{text:d[1]}),h("span",{class:"who",text:WHO[e.actor]||e.actor||""})),
      h("time",{datetime:e.at,title:new Date(e.at).toLocaleString(),text:relTime(e.at)})));
  });
}

`;
