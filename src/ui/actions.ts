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
async function moveOrder(index,delta){
  const order=S.used.slice();
  const j=index+delta;
  if(j<0||j>=order.length)return;
  const t=order[j];order[j]=order[index];order[index]=t;
  await refresh(await api("/api/link",{order:order}));
}
async function ensureLibrary(){
  if(!S.global.exists){await api("/api/global",{create:true})}
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

  // Where it goes: the sets this project uses first, then its other sets, then the library.
  const sel=h("select",{class:"input"});
  const used=usedSets().filter(function(u){return u.set&&!u.placeholder});
  const g1=h("optgroup",{label:"Used here"});
  used.forEach(function(u){g1.append(h("option",{value:u.where+"|"+u.set.name},u.set.label+(u.where==="library"?"  · library":"")))});
  if(!used.some(function(u){return u.where==="project"&&u.set.name==="default"}))g1.append(h("option",{value:"project|default"},"default  · this project"));
  sel.append(g1);
  const others=S.project.filter(function(s){return S.used.indexOf(s.name)<0});
  if(others.length){const g=h("optgroup",{label:"This project"});others.forEach(function(s){g.append(h("option",{value:"project|"+s.name},s.label))});sel.append(g)}
  const lib=S.library.filter(function(s){return S.used.indexOf(s.name==="default"?"library:default":s.name)<0});
  if(lib.length){const g=h("optgroup",{label:"Library"});lib.forEach(function(s){g.append(h("option",{value:"library|"+s.name},s.label))});sel.append(g)}
  sel.append(h("optgroup",{label:"New"},h("option",{value:"new|project"},"New set in this project…"),h("option",{value:"new|library"},"New set in my library…")));
  if(prefill.target)sel.value=prefill.target;
  const newName=h("input",{class:"input",placeholder:"e.g. Stripe live"});
  const newWrap=field("New set name",newName);
  const useIt=h("input",{type:"checkbox",checked:true});
  const useWrap=h("label",{class:"check"},useIt,h("span",null,"Use this set in ",h("b",{text:folderName()})));
  const warn=h("div",{class:"banner warn",hidden:true});
  const note=h("input",{class:"input",placeholder:"e.g. live, read-only, expires June"});

  function target(){const v=sel.value.split("|");return {kind:v[0],where:v[0]==="new"?v[1]:v[0],name:v.slice(1).join("|")}}
  function check(){
    const t=target();
    newWrap.hidden=t.kind!=="new";
    const link=t.kind==="library"?(t.name==="default"?"library:default":t.name):t.name;
    useWrap.hidden=!(t.kind==="new"||(t.kind==="library"&&S.used.indexOf(link)<0)||(t.kind==="project"&&S.used.indexOf(t.name)<0));
    const list=t.where==="library"?S.library:S.project;
    const s=t.kind==="new"?null:list.find(function(x){return x.name===t.name});
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
      let where=t.where,scope=t.name;
      if(t.kind==="new"){
        if(!newName.value.trim()){toast("name the new set",{error:true});newName.focus();return false}
        if(where==="library")await ensureLibrary();
        const c=await api("/api/env",{action:"create",where:where,label:newName.value.trim()});
        scope=c.created;
      }else if(where==="library")await ensureLibrary();
      const r=await api("/api/secret",{scope:scope,key:k,value:v,where:where,note:note.value.trim()||undefined});
      let next=r;
      if(!useWrap.hidden&&useIt.checked){
        next=await api("/api/link",{name:where==="library"&&scope==="default"?"library:default":scope,use:true});
      }
      await refresh(next);
      toast(r.vaultCreated?VAULT_MADE:"saved "+k);
    },
  });
}

function newSetDialog(where){
  const name=h("input",{class:"input",placeholder:where==="library"?"e.g. Personal OpenAI":"e.g. Staging"});
  const desc=h("input",{class:"input",placeholder:"Live Stripe and Postgres for deploys"});
  const svc=h("select",{class:"input"},h("option",{value:""},"No — I'll add keys myself"));
  S.catalog.forEach(function(c){svc.append(h("option",{value:c.id},c.label+"  ("+c.vars.join(", ")+")"))});
  const useIt=h("input",{type:"checkbox",checked:where==="project"});
  dialog({
    title:where==="library"?"New set in your library":"New set in this project",
    lead:where==="library"?"Yours alone, on this machine. Any project can add it later."
      :"Committed with the project, so everyone on the team gets it.",
    submit:"Create set",
    body:[field("Name",name),field("What is it for? (optional)",desc,"Your agent reads this to pick the right set."),
      field("For a known service?",svc,"hush asks for exactly the variables it needs."),
      h("label",{class:"check"},useIt,h("span",null,"Use it in ",h("b",{text:folderName()})))],
    onSubmit:async function(){
      const label=name.value.trim();
      if(!label){toast("give it a name",{error:true});name.focus();return false}
      if(where==="library")await ensureLibrary();
      const r=await api("/api/env",{action:"create",where:where,label:label,description:desc.value.trim()||undefined,service:svc.value||undefined});
      let next=r;
      if(useIt.checked)next=await api("/api/link",{name:where==="library"&&r.created==="default"?"library:default":r.created,use:true});
      await refresh(next);
      toast(r.vaultCreated?VAULT_MADE:"created "+label);
      if(r.vars&&r.vars.length)serviceValuesDialog(where,r.created,label,r.vars);
    },
  });
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

function moveDialog(where,fromSet,key){
  const list=(where==="library"?S.library:S.project).filter(function(x){return x.name!==fromSet.name});
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

/* ------------------------------------------------------------- set cards */

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
  return h("div",{class:"krow"+(over?" over":"")},
    h("div",{class:"kname"},h("span",{class:"k",text:s.key,title:s.key}),sub.length?h("div",{class:"sub"},sub):null),
    bar,
    h("div",{class:"kact"},rv,moreButton("More for "+s.key,[
      {label:"Replace value…",run:function(){replaceDialog(where,set.name,s.key)}},
      where==="project"?{label:s.note?"Edit tag…":"Add a tag…",run:function(){tagDialog(set.name,s.key,s.note)}}:null,
      (where==="library"?S.library:S.project).length>1?{label:"Move to another set…",run:function(){moveDialog(where,set,s.key)}}:null,
      "-",
      {label:"Delete "+s.key,danger:true,run:function(){confirmDialog("Delete "+s.key+"?","It is removed from "+set.label+". This cannot be undone.","Delete",function(){return setSecret(set.name,s.key,null,where)})}},
    ])));
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
 * ctx.order adds the position badge and up/down; ctx.useToggle adds the
 * library's use-here button.
 */
function setCard(where,set,ctx){
  ctx=ctx||{};
  const link=ctx.link||set.name;
  const tools=h("div",{class:"tools"});
  if(ctx.order){
    tools.append(h("button",{type:"button",class:"iconbtn","aria-label":"Apply "+set.label+" earlier",disabled:ctx.order.index===0,
      onclick:function(){moveOrder(ctx.order.index,-1)}},icon("up")));
    tools.append(h("button",{type:"button",class:"iconbtn","aria-label":"Apply "+set.label+" later",disabled:ctx.order.index===S.used.length-1,
      onclick:function(){moveOrder(ctx.order.index,1)}},icon("down")));
  }
  if(ctx.useToggle&&set.usableHere===false&&S.used.indexOf(link)<0){
    // Kept for other folders: say so where the button would be, not after a click.
    tools.append(h("button",{type:"button",class:"btn sm",disabled:true,title:"Only for "+set.onlyIn.join(", ")},"Other folders only"));
  }else if(ctx.useToggle){
    const used=S.used.indexOf(link)>-1;
    tools.append(h("button",{type:"button",class:"btn sm"+(used?" on":""),onclick:function(){useHere(link,set.label,!used)},
      title:used?"Stop using it in "+folderName():null},used?[icon("check"),"Used here"]:"Use here"));
  }
  const floor=where==="project"&&set.name==="default";
  tools.append(moreButton("More for "+set.label,function(){return [
    {label:"Add a key…",run:function(){addSecretDialog({target:where+"|"+set.name})}},
    {label:"Edit name and description…",run:function(){editSetDialog(where,set)}},
    ctx.order&&!floor?{label:"Stop using here",run:function(){useHere(link,set.label,false)}}:null,
    "-",
    floor?null:{label:"Delete set…",danger:true,run:function(){deleteSetDialog(where,set)}},
  ]}));

  const top=h("div",{class:"top"},
    ctx.order?h("div",{class:"ord",title:"Applied in position "+(ctx.order.index+1)},String(ctx.order.index+1)):null,
    h("div",{class:"title"},h("b",{text:set.label}),
      h("span",{class:"badge"},where==="library"?"Library":"Project"),
      h("span",{class:"count",text:plural(set.keys.length,"key")})),
    tools);
  const card=h("article",{class:"card set"+(ctx.order?" ordered":""),"aria-label":set.label},top);
  const bits=[];
  if(set.description)bits.push(set.description);
  if(set.whenToUse)bits.push("Use for: "+set.whenToUse);
  if(set.onlyIn&&set.onlyIn.length)bits.push("Only in "+set.onlyIn.join(", ")+(set.usableHere===false?" — not usable in this folder":""));
  if(floor&&!set.description)bits.push("Always applied first. Keys that only this project needs go here.");
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
