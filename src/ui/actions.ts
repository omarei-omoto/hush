/**
 * What the page can do — add, reveal, move, rename, remove — and the set cards they act on.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const ACTIONS = String.raw`/* --------------------------------------------------------------- actions */

async function setSecret(scope,key,value,where){
  const r=await api("/api/secret",{scope:scope,key:key,value:value,where:where});
  await refresh(r);
  toast(r.vaultCreated?VAULT_MADE:(value===null?"deleted "+key:"saved "+key));
  return r;
}
async function retag(scope,key,note){
  await refresh(await api("/api/tag",{scope:scope,key:key,note:note}));
  toast(note?"tagged "+key:"tag cleared");
}
async function useHere(link,label,use){
  await refresh(await api("/api/link",{name:link,use:use!==false}));
  toast(use===false?"stopped using "+label+" here":label+" is now used here",
    use===false?null:{action:{label:"Undo",run:function(){useHere(link,label,false)}}});
}
/* Two things this project uses give the same key: the later one wins, so move this one last. */
async function letWin(link,label){
  const order=S.used.filter(function(l){return l!==link}).concat([link]);
  await refresh(await api("/api/link",{order:order}));
  toast(label+" wins now");
}
async function ensureLibrary(){
  if(!S.global.exists){await api("/api/global",{create:true})}
}

/**
 * This project's own set for single keys: the one named after it, in your
 * library and kept for this project only. Made, and used here, the first
 * time a key needs it. Returns its name.
 */
async function ownSetName(){
  const name=folderName();
  const have=S.library.find(function(x){return x.own&&x.label===name});
  if(have)return have.name;
  await ensureLibrary();
  const c=await api("/api/env",{action:"create",where:"library",own:true,label:name});
  await api("/api/link",{name:c.created,use:true});
  return c.created;
}

/** Add a secret: the one thing people come here to do most. */
function addSecretDialog(prefill){
  prefill=prefill||{};
  const KEY_RE=/^[A-Za-z_][A-Za-z0-9_]*$/;
  const key=h("input",{class:"input mono",placeholder:"STRIPE_SECRET_KEY",autocomplete:"off",spellcheck:"false",value:prefill.key||""});
  key.addEventListener("input",function(){const p=key.selectionStart;key.value=key.value.toUpperCase().replace(/\s+/g,"_");key.setSelectionRange(p,p);check()});
  const single=h("input",{class:"input mono",type:"password",autocomplete:"new-password",spellcheck:"false",placeholder:"paste the value"});
  const multi=h("textarea",{class:"input",spellcheck:"false",placeholder:"-----BEGIN PRIVATE KEY-----",hidden:true});
  const shape=h("button",{type:"button",class:"linkbtn",onclick:function(){
    const toMulti=multi.hidden;multi.hidden=!toMulti;single.hidden=toMulti;
    (toMulti?multi:single).value=(toMulti?single:multi).value;shape.textContent=toMulti?"Single line":"Multi-line value";
    (toMulti?multi:single).focus();
  }},"Multi-line value");
  const reveal=h("button",{type:"button",class:"linkbtn",onclick:function(){single.type=single.type==="password"?"text":"password";reveal.textContent=single.type==="password"?"Show":"Hide"}},"Show");

  // Where it goes: this project's own keys first, then your global ones.
  const name0=folderName();
  const sel=h("select",{class:"input"});
  const own=S.library.filter(function(x){return x.own});
  const g1=h("optgroup",{label:"Only "+name0});
  if(!own.some(function(x){return x.label===name0}))g1.append(h("option",{value:"own|"},name0+"  · its own keys"));
  own.forEach(function(s){g1.append(h("option",{value:"library|"+s.name},s.label))});
  S.project.forEach(function(s){g1.append(h("option",{value:"project|"+s.name},s.label+"  · in the repo, shared with the team"))});
  g1.append(h("option",{value:"new|own"},"New set for "+name0+" only…"));
  sel.append(g1);
  const g2=h("optgroup",{label:"Global — any project can use it"});
  globalSets().forEach(function(s){g2.append(h("option",{value:"library|"+s.name},s.label+(s.group?"  · "+s.group:"")))});
  if(!globalSets().some(function(s){return s.name==="default"}))g2.append(h("option",{value:"library|default"},"Catch-all"));
  g2.append(h("option",{value:"new|library"},"New global set…"));
  sel.append(g2);
  sel.value=prefill.target||(route()==="library"?"library|default":(own.find(function(x){return x.label===name0})?"library|"+own.find(function(x){return x.label===name0}).name:"own|"));
  const newName=h("input",{class:"input",placeholder:"e.g. Stripe live"});
  const newWrap=field("New set name",newName);
  const useIt=h("input",{type:"checkbox",checked:true});
  const useWrap=h("label",{class:"check"},useIt,h("span",null,"Use this set in ",h("b",{text:name0})));
  const warn=h("div",{class:"banner warn",hidden:true});
  const note=h("input",{class:"input",placeholder:"e.g. live, read-only, expires June"});

  function target(){const v=sel.value.split("|");return {kind:v[0],where:v[0]==="new"?v[1]:v[0],name:v.slice(1).join("|")}}
  function pick(t){
    if(t.kind==="library")return S.library.find(function(x){return x.name===t.name});
    if(t.kind==="project")return S.project.find(function(x){return x.name===t.name});
    if(t.kind==="own")return own.find(function(x){return x.label===name0});
    return null;
  }
  function check(){
    const t=target();
    newWrap.hidden=t.kind!=="new";
    const s=pick(t);
    // A project's own keys are always used there; a global set or a repo set only when you say so.
    const ownTarget=t.where==="own"||(s&&s.own);
    useWrap.hidden=ownTarget||!(t.kind==="new"||(s&&S.used.indexOf(t.kind==="library"?linkOf(s):s.name)<0)||(!s&&t.kind==="library"));
    const exists=s&&s.keys.indexOf(key.value)>-1;
    warn.hidden=!exists;
    clear(warn);if(exists)warn.append(icon("alert"),h("span",{text:key.value+" is already in "+s.label+" — saving replaces it."}));
  }
  sel.onchange=check;check();

  dialog({
    title:"Add a secret",
    lead:"Stored encrypted. It never comes back to this page unless you reveal it.",
    submit:"Save secret",
    body:[
      field("Name",key),
      h("div",{class:"field"},h("span",{style:"display:flex;justify-content:space-between"},"Value",h("span",{style:"display:flex;gap:12px;font-weight:400"},reveal,shape)),single,multi),
      field("Save to",sel),newWrap,useWrap,warn,
      field("Tag (optional)",note,"A word to tell values apart, like live or test. Not secret."),
    ],
    onSubmit:async function(){
      const k=key.value.trim();
      const v=multi.hidden?single.value:multi.value;
      if(!KEY_RE.test(k)){toast("a name is letters, digits and _, not starting with a digit",{error:true});key.focus();return false}
      if(!v){toast("paste a value first",{error:true});return false}
      const t=target();
      let where=t.kind==="project"?"project":"library",scope=t.name,link=false;
      if(t.kind==="own"){
        scope=await ownSetName();
      }else if(t.kind==="new"){
        if(!newName.value.trim()){toast("name the new set",{error:true});newName.focus();return false}
        await ensureLibrary();
        const c=await api("/api/env",{action:"create",where:"library",own:t.where==="own",label:newName.value.trim()});
        scope=c.created;
        link=t.where==="own"||useIt.checked;
      }else{
        if(where==="library")await ensureLibrary();
        const s=pick(t);
        const used=S.used.indexOf(where==="library"?(s?linkOf(s):scope):scope)>-1;
        link=!used&&(s&&s.own?true:!useWrap.hidden&&useIt.checked);
      }
      const r=await api("/api/secret",{scope:scope,key:k,value:v,where:where,note:note.value.trim()||undefined});
      let next=r;
      if(link)next=await api("/api/link",{name:where==="library"&&scope==="default"?"library:default":scope,use:true});
      await refresh(next);
      toast(r.vaultCreated?VAULT_MADE:"saved "+k);
    },
  });
}

/*
 * "New…" in a list of names: marked by an attribute rather than a value, so
 * no group or set a person names can ever be taken for it.
 */
function newOption(text){return h("option",{value:"","data-new":"1",text:text})}
function newPicked(sel){const o=sel.options[sel.selectedIndex];return Boolean(o&&o.hasAttribute("data-new"))}
function pickNew(sel){[].forEach.call(sel.options,function(o){if(o.hasAttribute("data-new"))o.selected=true})}

/** A group to file a global set under: one there is, a new one, or none. */
function groupChooser(current){
  const sel=h("select",{class:"input"});
  sel.append(h("option",{value:"",text:"No group"}));
  (S.groups||[]).forEach(function(g){sel.append(h("option",{value:g.label},g.label))});
  sel.append(newOption("New group…"));
  sel.value=current||"";
  const name=h("input",{class:"input",placeholder:"e.g. AI stack"});
  const nameWrap=field("New group's name",name);
  function sync(){nameWrap.hidden=!newPicked(sel)}
  sel.onchange=sync;sync();
  const box=h("div",{class:"stack"},field("Group (optional)",sel,"A folder for your global keys. A project given the group gets every set in it."),nameWrap);
  return {
    el:box,
    /* "" for no group; null when "New group…" is picked but not named yet. */
    value:function(){return newPicked(sel)?(name.value.trim()||null):sel.value},
  };
}

/** where: "own" (only this project, in your library), "library" (global) or "project" (the repository's vault). */
function newSetDialog(where){
  const own=where==="own";
  const name=h("input",{class:"input",placeholder:where==="library"?"e.g. Personal OpenAI":"e.g. Stripe test"});
  const desc=h("input",{class:"input",placeholder:"Live Stripe and Postgres for deploys"});
  const svc=h("select",{class:"input"},h("option",{value:""},"No — I'll add keys myself"));
  S.catalog.forEach(function(c){svc.append(h("option",{value:c.id},c.label+"  ("+c.vars.join(", ")+")"))});
  const onProject=route()==="project"&&S.folder.state!=="unset";
  const useIt=h("input",{type:"checkbox",checked:where==="project"||onProject});
  const grp=where==="library"?groupChooser(""):null;
  dialog({
    title:own?"New set for "+folderName():where==="library"?"New global set":"New set in the repository",
    lead:own?"Only "+folderName()+" gets it, and hush refuses it anywhere else. Yours alone, never in the repository."
      :where==="library"?"Yours alone. Any project can use it: drag it onto one."
      :"Committed with the project, so everyone on the team gets it.",
    submit:"Create set",
    body:[field("Name",name),field("What is it for? (optional)",desc,"Your agent reads this to pick the right set."),
      field("For a known service?",svc,"hush asks for exactly the variables it needs."),
      grp?grp.el:null,
      own?null:h("label",{class:"check"},useIt,h("span",null,"Use it in ",h("b",{text:folderName()})))],
    onSubmit:async function(){
      const label=name.value.trim();
      if(!label){toast("give it a name",{error:true});name.focus();return false}
      if(where!=="project")await ensureLibrary();
      const r=await api("/api/env",{action:"create",where:own?"library":where,own:own,label:label,description:desc.value.trim()||undefined,service:svc.value||undefined});
      let next=r;
      if(grp&&grp.value())next=await api("/api/group",{action:"file",set:r.created,group:grp.value()});
      if(own||useIt.checked)next=await api("/api/link",{name:where!=="project"&&r.created==="default"?"library:default":r.created,use:true});
      await refresh(next);
      toast(r.vaultCreated?VAULT_MADE:"created "+label);
      if(r.vars&&r.vars.length)serviceValuesDialog(where==="project"?"project":"library",r.created,label,r.vars);
    },
  });
}

/* ---------------------------------------------------- making things global -- */

/** One of this project's own sets, made global: up into your global keys, still part of this project. */
function makeGlobalSetDialog(where,set){
  const grp=groupChooser("");
  const n=set.keys.length;
  dialog({title:"Make "+set.label+" global",
    lead:"Its "+plural(n,"key")+" join your global keys, so you can drag "+(n===1?"it":"them")+" onto any project. "+folderName()+" keeps getting "+(n===1?"it":"them")+"."+(where==="project"?" "+(n===1?"It leaves":"They leave")+" the repository's vault: global keys are yours alone.":""),
    submit:"Make it global",body:[grp.el],
    onSubmit:async function(){await place({action:"global",where:where,set:set.name,group:grp.value()||undefined})}});
}
/** One key of this project's own, made global: into a global set you pick, or a new one. */
function makeGlobalKeyDialog(where,set,k){
  const sel=h("select",{class:"input"});
  globalSets().filter(function(s){return s.name!=="default"}).forEach(function(s){sel.append(h("option",{value:s.name},s.label+(s.group?"  · "+s.group:"")))});
  sel.append(newOption("New global set…"));
  const service=S.catalog.find(function(c){return c.vars.indexOf(k)>-1});
  const fits=globalSets().find(function(s){return service&&s.label.toLowerCase()===service.label.toLowerCase()});
  if(fits)sel.value=fits.name;else pickNew(sel);
  const name=h("input",{class:"input",placeholder:"e.g. Stripe",value:service?service.label:""});
  const nameWrap=field("New set's name",name);
  const grp=groupChooser("");
  function sync(){const isNew=newPicked(sel);nameWrap.hidden=!isNew;grp.el.hidden=!isNew}
  sel.onchange=sync;
  dialog({title:"Make "+k+" global",
    lead:"It joins your global keys, in the set you pick, and stays part of "+folderName()+". Every project that uses that set gets it too.",
    submit:"Make it global",body:[field("Into",sel),nameWrap,grp.el],
    onSubmit:async function(){
      const isNew=newPicked(sel);
      if(isNew&&!name.value.trim()){toast("name the new set",{error:true});name.focus();return false}
      await place({action:"global",where:where,set:set.name,key:k,to:isNew?undefined:sel.value,toLabel:isNew?name.value.trim():undefined,group:isNew?(grp.value()||undefined):undefined});
    }});
  sync();
}

function serviceValuesDialog(where,scope,label,vars){
  const inputs=vars.map(function(v){return {key:v,input:h("input",{class:"input mono",type:"password",autocomplete:"new-password",spellcheck:"false"})}});
  dialog({
    title:"Fill in "+label,lead:"Leave any blank to add it later.",submit:"Save values",
    body:inputs.map(function(it){return field(it.key,it.input)}),
    onSubmit:async function(){
      let n=0;
      for(const it of inputs){if(!it.input.value)continue;await api("/api/secret",{where:where,scope:scope,key:it.key,value:it.input.value});n++}
      await refresh();toast("saved "+plural(n,"value"));
    },
  });
}

function editSetDialog(where,set){
  const name=h("input",{class:"input",value:set.label});
  const desc=h("input",{class:"input",value:set.description||"",placeholder:"What is it for?"});
  const when=h("input",{class:"input",value:set.whenToUse||"",placeholder:"e.g. deploys only, never in tests"});
  const before=(set.onlyIn||[]).join("\n");
  const only=h("textarea",{class:"input",rows:"2",spellcheck:"false",placeholder:"~/code/modio-*"});
  only.value=before;
  dialog({
    title:"Edit "+set.label,submit:"Save",
    body:[field("Name",name,set.name==="default"?"":"Renaming re-seals every value under the new name."),
      field("Description",desc),field("When to use it",when,"Shown to your agent when it picks a set."),
      field("Only in these folders",only,"One per line. Anywhere else, hush refuses this set — for you and your agent. Blank: any folder. * matches within a folder name, ** across folders.")],
    onSubmit:async function(){
      const label=name.value.trim();
      let next=null;
      if(label&&label!==set.label){next=await api("/api/env",{action:"rename",where:where,name:set.name,label:label})}
      const renamed=next&&next.renamed?next.renamed:set.name;
      const folders=only.value.split("\n").map(function(l){return l.trim()}).filter(Boolean);
      const foldersChanged=folders.join("\n")!==before;
      if(desc.value!==(set.description||"")||when.value!==(set.whenToUse||"")||foldersChanged){
        const payload={action:"describe",where:where,name:renamed,description:desc.value.trim(),whenToUse:when.value.trim()};
        if(foldersChanged)payload.onlyIn=folders;
        next=await api("/api/env",payload);
      }
      await refresh(next);toast("saved");
    },
  });
}

function deleteSetDialog(where,set){
  confirmDialog("Delete "+set.label+"?",
    plural(set.keys.length,"key")+" will be gone for good"+(where==="project"?" — for everyone, once you commit.":"."),
    "Delete set",
    async function(){await refresh(await api("/api/env",{action:"delete",where:where,name:set.name}));toast("deleted "+set.label)});
}

function replaceDialog(where,scope,key){
  const v=h("textarea",{class:"input",spellcheck:"false",placeholder:"paste the new value"});
  dialog({
    title:"Replace "+key,lead:"The old value is overwritten. Nothing is shown here.",submit:"Replace",
    body:[field("New value",v)],
    onSubmit:async function(){if(!v.value){toast("paste a value first",{error:true});return false}await setSecret(scope,key,v.value.replace(/\n$/,""),where)},
  });
}

/* Within one kind: global to global, this project's own to its own. "Make global" crosses over. */
function sameKind(where,set){
  if(where==="project")return S.project;
  return S.library.filter(function(x){return Boolean(x.own)===Boolean(set.own)});
}
function moveDialog(where,fromSet,key){
  const list=sameKind(where,fromSet).filter(function(x){return x.name!==fromSet.name});
  const sel=h("select",{class:"input"});
  list.forEach(function(s){sel.append(h("option",{value:s.name},s.label))});
  dialog({
    title:"Move "+key,lead:"From "+fromSet.label+". The value is re-sealed under its new set.",submit:"Move",
    body:[field("To",sel)],
    onSubmit:async function(){await refresh(await api("/api/move",{where:where,key:key,from:fromSet.name,to:sel.value}));toast("moved "+key+" to "+setLabel(where,sel.value))},
  });
}

function tagDialog(scope,key,current){
  const t=h("input",{class:"input",value:current||"",placeholder:"e.g. live"});
  dialog({title:"Tag "+key,submit:"Save",body:[field("Tag",t,"Leave empty to clear it.")],
    onSubmit:async function(){await retag(scope,key,t.value.trim())}});
}

/** Reveal: approval may pop up on the desktop first, so the bar says it is waiting. */
async function reveal(where,scope,key,bar,plain,btn){
  if(bar.classList.contains("open")){if(bar._hide)bar._hide();return}
  bar.classList.add("wait");btn.disabled=true;btn.lastChild.textContent="Waiting…";
  bar.setAttribute("aria-busy","true");
  let value;
  try{value=(await api("/api/reveal",{scope:scope,key:key,where:where})).value}
  catch(e){bar.classList.remove("wait");btn.disabled=false;btn.lastChild.textContent="Reveal";bar.removeAttribute("aria-busy");return}
  bar.classList.remove("wait");bar.removeAttribute("aria-busy");
  plain.textContent=value;
  bar.classList.add("open");btn.disabled=false;
  btn.replaceChildren(icon("eyeoff"),document.createTextNode("Hide"));
  const copy=h("button",{type:"button",class:"btn sm ghost",onclick:async function(){
    try{await navigator.clipboard.writeText(value);toast("copied "+key)}catch(e){toast("copying is blocked here — select the text instead",{error:true})}
  }},icon("copy"),"Copy");
  btn.after(copy);
  const timer=setTimeout(hide,15000);
  function hide(){clearTimeout(timer);bar.classList.remove("open");plain.textContent="";copy.remove();
    btn.replaceChildren(icon("eye"),document.createTextNode("Reveal"));}
  bar._hide=hide;
}

/* ------------------------------------------------------ sending to a host -- */

/* The hosts hush can send to, and which this project's files name (GET-like /api/push-hosts). */
let PUSH_HOSTS=null;
async function pushHosts(){if(!PUSH_HOSTS||PUSH_HOSTS.root!==currentRoot()){PUSH_HOSTS=await api("/api/push-hosts",{});PUSH_HOSTS.root=currentRoot()}return PUSH_HOSTS}

/**
 * Send one key's value to a host: hush runs the host's own CLI on this
 * machine with the value on its standard input (src/push.ts). preset picks
 * the host, target and environment — "send it again" from where it went.
 */
async function pushDialog(where,set,key,preset){
  preset=preset||{};
  const ph=await pushHosts();
  const detected=ph.detected||[];
  const here=ph.hosts.filter(function(x){return detected.some(function(d){return d.id===x.id})});
  const rest=ph.hosts.filter(function(x){return here.indexOf(x)<0});
  const sel=h("select",{class:"input"});
  if(here.length){const g=h("optgroup",{label:"This project deploys to"});here.forEach(function(x){g.append(h("option",{value:x.id},x.label))});sel.append(g)}
  const g2=h("optgroup",{label:here.length?"Other hosts":"Hosts"});rest.forEach(function(x){g2.append(h("option",{value:x.id},x.label))});sel.append(g2);
  sel.value=preset.host||(here[0]||rest[0]).id;
  const target=h("input",{class:"input mono",autocomplete:"off",spellcheck:"false"});
  const targetName=h("span");
  const targetHint=h("small");
  const targetWrap=h("label",{class:"field"},targetName,target,targetHint);
  const envName=h("span");
  const envBox=h("div");
  const envWrap=h("label",{class:"field"},envName,envBox);
  let envCtl=null;
  const deploy=h("input",{type:"checkbox"});
  const deployWrap=h("label",{class:"check"},deploy,h("span",{text:"Deploy now, as part of setting it"}));
  const note=h("p",{class:"muted",style:"margin:0;font-size:13px"});
  function host(){return ph.hosts.find(function(x){return x.id===sel.value})}
  function sync(first){
    const x=host();
    const found=detected.find(function(d){return d.id===x.id});
    targetWrap.hidden=!x.target;
    if(x.target){
      targetName.textContent=x.target.noun.charAt(0).toUpperCase()+x.target.noun.slice(1)+(x.target.required?"":" (optional)");
      target.value=(first&&preset.target)||(found&&found.target)||"";
      targetHint.textContent=found&&found.target?"From this project's own config.":x.target.required?"":"Leave empty for the one its CLI is linked to.";
    }
    envWrap.hidden=!x.env;
    clear(envBox);envCtl=null;
    if(x.env){
      envName.textContent=x.env.noun.charAt(0).toUpperCase()+x.env.noun.slice(1)+(x.env.required?"":" (optional)");
      if(x.env.choices){envCtl=h("select",{class:"input"});x.env.choices.forEach(function(c){envCtl.append(h("option",{value:c},c))});envCtl.value=(first&&preset.env)||x.env.default||x.env.choices[0]}
      else envCtl=h("input",{class:"input mono",autocomplete:"off",spellcheck:"false",value:(first&&preset.env)||""});
      envBox.append(envCtl);
    }
    deployWrap.hidden=x.deploys!=="optional";
    note.textContent=x.after;
  }
  sel.onchange=function(){sync(false)};sync(true);
  dialog({title:"Send "+key+" to a host",
    lead:"hush runs that host's own CLI here, with the value on its standard input — never on a command line, and never through this page. It refuses a value the CLI would change, and an old CLI.",
    submit:"Send",body:[field("Host",sel),targetWrap,envWrap,deployWrap,note],
    onSubmit:async function(){
      const r=await api("/api/push",{where:where,set:set.name,key:key,to:sel.value,
        target:target.value.trim()||undefined,env:envCtl&&envCtl.value.trim()?envCtl.value.trim():undefined,deploy:!deployWrap.hidden&&deploy.checked});
      await refresh(r);
      toast(r.done,r.ok?null:{error:true});
      if(!r.ok&&r.output&&r.output.trim())cliOutputDialog(host().label,r.output);
    }});
}
function cliOutputDialog(label,output){
  dialog({title:label+" said",lead:"Its output, with the value masked.",noSubmit:true,cancel:"Close",wide:true,
    body:[h("pre",{class:"cliout mono",text:output.trim().slice(-6000)})]});
}

/* ------------------------------------------------------------- set cards */

/** link: what this project lists to get the set the row is in (its own name, a group, …), when it does. */
function keyRow(where,set,s,win,link){
  const over=win&&win[s.key]&&win[s.key].link!==link;
  const plain=h("div",{class:"plain"});
  const masked=h("div",{class:"masked",text:s.preview});
  const bar=h("div",{class:"bar",title:over?"not used: "+win[s.key].label+" overrides it":null},plain,masked,h("div",{class:"timer"}));
  const rv=h("button",{type:"button",class:"btn sm ghost","aria-label":"Reveal "+s.key},icon("eye"),"Reveal");
  rv.onclick=function(){reveal(where,set.name,s.key,bar,plain,rv)};
  const sub=[];
  if(s.note)sub.push(h("span",{class:"tag",text:s.note}));
  if(over)sub.push(h("span",{text:"overridden by "+win[s.key].label}));
  // Where this value was sent (hush push), and whether it changed since.
  (S.pushes||[]).filter(function(p){return p.key===s.key&&(!p.set||p.set===set.name)}).forEach(function(p){
    sub.push(h("button",{type:"button",class:"sent"+(p.stale?" stale":""),
      title:(p.stale?"Changed since it was sent — click to send the new value. ":"Sent ")+ago(p.at)+(p.stale?"":" — click to send it again"),
      onclick:function(){pushDialog(where,set,s.key,{host:p.host,target:p.target,env:p.env})}},
      icon("arrowup"),p.label+(p.target?" · "+p.target:"")+(p.env?" ("+p.env+")":""),p.stale?" · old value there":""));
  });
  // A global key can be dragged onto any project; one of this project's own goes global first.
  const global=where==="library"&&!set.own&&set.name.indexOf("#")<0;
  const own=isOwn(where,set);
  const onProject=route()==="project"&&S.folder.state!=="unset";
  const usedHere=onProject&&link&&S.used.indexOf(link)>-1;
  const row=h("div",{class:"krow"+(over?" over":"")},
    h("div",{class:"kname"},h("div",{class:"kline"},global?h("span",{class:"grip","aria-hidden":"true"},icon("grip")):null,h("span",{class:"k",text:s.key,title:global?"Drag onto a project to use it there":s.key})),sub.length?h("div",{class:"sub"},sub):null),
    bar,
    h("div",{class:"kact"},rv,moreButton("More for "+s.key,function(){return [
      own&&onProject?{label:"Make global…",run:function(){makeGlobalKeyDialog(where,set,s.key)}}:null,
      global&&usedHere?{label:"Keep for "+folderName()+" only",run:function(){place({action:"here",set:set.name,key:s.key})}}:null,
      onProject&&set.name.indexOf("#")<0?{label:"Send to a host…",run:function(){pushDialog(where,set,s.key)}}:null,
      global?{label:"Use in a project…",run:function(){giveKeyDialog({kind:"key",set:set.name,key:s.key})}}:null,
      {label:"Replace value…",run:function(){replaceDialog(where,set.name,s.key)}},
      where==="project"?{label:s.note?"Edit tag…":"Add a tag…",run:function(){tagDialog(set.name,s.key,s.note)}}:null,
      sameKind(where,set).length>1?{label:"Move to another set…",run:function(){moveDialog(where,set,s.key)}}:null,
      "-",
      {label:"Delete "+s.key,danger:true,run:function(){confirmDialog("Delete "+s.key+"?","It is removed from "+set.label+". This cannot be undone.","Delete",function(){return setSecret(set.name,s.key,null,where)})}},
    ]})));
  if(global)draggableKey(row,set.name,s.key);
  return row;
}

const OPEN_ADD={};
function addKeyRow(where,set){
  const id=where+":"+set.name;
  const wrap=h("div",{class:"addkey"});
  if(!OPEN_ADD[id]){
    wrap.append(h("button",{type:"button",class:"btn sm ghost",onclick:function(){OPEN_ADD[id]=true;render();
      const k=document.querySelector("[data-add='"+CSS.escape(id)+"'] input");if(k)k.focus()}},icon("plus"),"Add key"));
    return wrap;
  }
  const k=h("input",{class:"input mono",placeholder:"KEY","aria-label":"New key name in "+set.label,autocomplete:"off",spellcheck:"false"});
  k.addEventListener("input",function(){k.value=k.value.toUpperCase().replace(/\s+/g,"_")});
  const v=h("input",{class:"input mono",type:"password",placeholder:"value","aria-label":"Value","autocomplete":"new-password"});
  const f=h("form",{"data-add":id},k,v,h("button",{type:"submit",class:"btn sm primary"},"Add"),
    h("button",{type:"button",class:"btn sm ghost",onclick:function(){delete OPEN_ADD[id];render()}},"Cancel"));
  f.onsubmit=async function(ev){
    ev.preventDefault();
    if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k.value)){toast("a name is letters, digits and _",{error:true});k.focus();return}
    if(!v.value){v.focus();return}
    try{await setSecret(set.name,k.value,v.value,where)}catch(e){}
  };
  f.addEventListener("keydown",function(ev){if(ev.key==="Escape"){delete OPEN_ADD[id];render()}});
  wrap.append(f);
  return wrap;
}

/**
 * One set: its name and where it lives, what it is for, and every key in it.
 * ctx.here: shown on a project page as one it uses (ctx.link is how it is
 * listed there). ctx.useToggle adds Global keys' use-here button.
 */
function setCard(where,set,ctx){
  ctx=ctx||{};
  const link=ctx.link||(where==="library"?linkOf(set):set.name);
  const own=isOwn(where,set);
  const global=where==="library"&&!set.own;
  const onProject=route()==="project"&&S.folder.state!=="unset";
  const usedHere=S.used.indexOf(link)>-1;
  const floor=where==="project"&&set.name==="default";
  const tools=h("div",{class:"tools"});
  if(ctx.here&&own&&set.keys.length){
    tools.append(h("button",{type:"button",class:"btn sm",title:"Make "+set.label+" one of your global keys — "+folderName()+" keeps getting it",
      onclick:function(){makeGlobalSetDialog(where,set)}},icon("arrowup"),"Make global"));
  }
  // Already used here as part of a group it is in.
  const viaGroup=global&&set.group?(S.groups||[]).find(function(g){return g.used&&g.sets.indexOf(set.name)>-1}):null;
  if(ctx.useToggle&&set.usableHere===false&&!usedHere){
    // Kept for other folders: say so where the button would be, not after a click.
    tools.append(h("button",{type:"button",class:"btn sm",disabled:true,title:"Only for "+set.onlyIn.join(", ")},"Other folders only"));
  }else if(ctx.useToggle&&viaGroup&&!usedHere){
    tools.append(h("button",{type:"button",class:"btn sm on",disabled:true,title:folderName()+" uses the whole group "+viaGroup.label},icon("check"),"Used through "+viaGroup.label));
  }else if(ctx.useToggle&&S.folder.state!=="unset"){
    tools.append(h("button",{type:"button",class:"btn sm"+(usedHere?" on":""),onclick:function(){useHere(link,set.label,!usedHere)},
      title:usedHere?"Stop using it in "+folderName():"Use it in "+folderName()},usedHere?[icon("check"),"Used here"]:"Use here"));
  }
  tools.append(moreButton("More for "+set.label,function(){return [
    {label:"Add a key…",run:function(){addSecretDialog({target:(where==="project"?"project|":"library|")+set.name})}},
    {label:"Edit name and description…",run:function(){editSetDialog(where,set)}},
    own&&onProject&&set.keys.length?{label:"Make global…",run:function(){makeGlobalSetDialog(where,set)}}:null,
    global&&set.name!=="default"?{label:set.group?"Move to another group…":"Put in a group…",run:function(){groupPickDialog(set)}}:null,
    global?{label:"Use in a project…",run:function(){giveKeyDialog({kind:"set",set:set.name})}}:null,
    global&&set.name!=="default"&&onProject&&usedHere?{label:"Keep for "+folderName()+" only",run:function(){place({action:"here",set:set.name})}}:null,
    ctx.here&&!floor?{label:"Stop using here",run:function(){useHere(link,set.label,false)}}:null,
    "-",
    floor?null:{label:"Delete set…",danger:true,run:function(){deleteSetDialog(where,set)}},
  ]}));

  const badge=where==="project"?h("span",{class:"badge",title:"In .hush/vault.json: everyone on the team who can open it gets these"},"In the repo")
    :set.own?h("span",{class:"badge"},"Only here")
    :h("span",{class:"badge ok"},"Global");
  const top=h("div",{class:"top"},
    h("div",{class:"title"},h("b",{text:set.label}),badge,
      global&&set.group?h("span",{class:"badge"},icon("folder"),set.group):null,
      h("span",{class:"count",text:plural(set.keys.length,"key")})),
    tools);
  const card=h("article",{class:"card set","aria-label":set.label},top);
  const bits=[];
  if(set.description)bits.push(set.description);
  if(set.whenToUse)bits.push("Use for: "+set.whenToUse);
  // A set kept for this project carries its folder as its only-in rule; saying so again is noise.
  if(!set.own&&set.onlyIn&&set.onlyIn.length)bits.push("Only in "+set.onlyIn.join(", ")+(set.usableHere===false?" — not usable in this folder":""));
  if(floor&&!set.description)bits.push("Committed in the repository's vault: everyone on the team gets these.");
  if(bits.length)card.append(h("div",{class:"desc",text:bits.join(" · ")}));
  if(set.secrets&&set.secrets.length){
    const keys=h("div",{class:"keys"});
    set.secrets.forEach(function(s){keys.append(keyRow(where,set,s,ctx.winners,link))});
    card.append(keys);
  }
  card.append(addKeyRow(where,set));
  return card;
}

`;
