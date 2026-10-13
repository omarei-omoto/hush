/**
 * Importing a .env (review before anything is saved), dropping files anywhere, and the shell that routes between sections.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const IMPORT = String.raw`/* ------------------------------------------------------ import a .env -- */

let STAGES=[];        // [{stageId,file,entries,rejected}]
let CHOICE={};        // stageId|key -> {scope,note,include}   (per row, not per name)
let OVERWRITE=false;
let DROP_WHERE=null;  // where the page that started the import wants it to go
let importing=false;
let reviewDlg=null;

/* Two dropped files may each define the same variable; keep their rows apart. */
function ck(stageId,key){return stageId+"|"+key}

/* Matches the server's limits, so an impossible file is refused before the tab
   tries to hold it in memory rather than after. */
const MAX_DROP_BYTES=2*1024*1024;
const MAX_DROP_FILES=20;

async function ingestFiles(files){
  let list=[].slice.call(files);
  if(!list.length)return;
  if(list.length>MAX_DROP_FILES){toast("taking the first "+MAX_DROP_FILES+" files");list=list.slice(0,MAX_DROP_FILES)}
  let added=0;
  for(const f of list){
    if(f.size>MAX_DROP_BYTES){toast(f.name+" is too large to be a .env",{error:true});continue}
    let text;
    try{text=await f.text()}catch(err){toast("could not read "+f.name,{error:true});continue}
    try{
      const st=await api("/api/stage",{text:text,filename:f.name});
      if(!st.entries.length&&!st.rejected.length){toast("no variables in "+f.name);continue}
      STAGES.push(st);
      st.entries.forEach(function(e){CHOICE[ck(st.stageId,e.key)]={scope:e.suggestedScope,note:e.service||"",include:true}});
      added++;
    }catch(err){/* api() already reported it */}
  }
  if(added)openReview();
}

function allScopes(){
  const out=[];
  (S.project||[]).forEach(function(e){out.push(e.name)});
  if(out.indexOf("default")<0)out.unshift("default");
  return out;
}
function scopeSelect(cid){
  const sel=h("select",{class:"input","aria-label":"Set for this key"});
  allScopes().forEach(function(sc){sel.append(h("option",{value:sc},setLabel("project",sc)))});
  sel.value=CHOICE[cid].scope;
  if(sel.value!==CHOICE[cid].scope){sel.append(h("option",{value:CHOICE[cid].scope},CHOICE[cid].scope));sel.value=CHOICE[cid].scope}
  sel.onchange=function(){CHOICE[cid].scope=sel.value};
  return sel;
}
function stagedCount(){return Object.keys(CHOICE).filter(function(k){return CHOICE[k].include}).length}
function dropCard(){
  return h("button",{type:"button",class:"btn",onclick:function(){document.getElementById("picker").click()}},icon("upload"),"Import .env");
}

async function discardStages(){
  const ids=STAGES.map(function(st){return st.stageId});
  STAGES=[];CHOICE={};
  if(ids.length){try{await api("/api/discard",{stageIds:ids})}catch(err){}}
}

function openReview(){
  if(reviewDlg){reviewDlg.close();reviewDlg=null}
  const panel=stagingPanel();
  reviewDlg=dialog({wide:true,title:panel.title,lead:panel.lead,body:panel.body,noSubmit:true,cancel:"Discard",
    left:panel.left,
    // Enter in a field means "save", never "close and throw it away".
    onSubmit:function(){panel.footer[0].click();return false},
    onClose:function(){reviewDlg=null;if(STAGES.length&&!importing){discardStages();toast("discarded — nothing was saved")}}});
  panel.footer.forEach(function(b){reviewDlg.el.querySelector(".df").append(b)});
}

/**
 * The review of dropped files. The common case is one click: save all of it
 * as one named set, in the library when there is one. Filing keys into
 * existing sets one by one is there for when a file is a mix.
 */
function stagingPanel(){
  let total=0;STAGES.forEach(function(st){total+=st.entries.length});
  const files=STAGES.map(function(st){return st.file}).join(", ");
  const guess=STAGES.length===1?(STAGES[0].file||"").replace(/^\.env\.?/,"").replace(/[-_.]+/g," ").trim():"";
  const name=h("input",{class:"input",placeholder:"e.g. Acme Production",value:guess?guess.charAt(0).toUpperCase()+guess.slice(1):""});
  const desc=h("input",{class:"input",placeholder:"What is it for? (optional)"});
  // The library first when there is one: a dropped .env is usually yours.
  const dest=h("div",{class:"seg",role:"radiogroup","aria-label":"Where to keep it"},
    h("label",null,h("input",{type:"radio",name:"dest",value:"library"}),h("span",null,"My library")),
    h("label",null,h("input",{type:"radio",name:"dest",value:"project"}),h("span",null,"This project")));
  const destValue=function(){const c=dest.querySelector("input:checked");return c?c.value:"project"};
  dest.querySelector("input[value="+(DROP_WHERE||(S.global.exists?"library":"project"))+"]").checked=true;
  DROP_WHERE=null;
  const destHint=h("small",{class:"muted"});
  function hint(){destHint.textContent=destValue()==="library"?"Yours alone. This project starts using it right away.":"Committed with the project — the whole team gets it."}
  dest.addEventListener("change",hint);hint();

  const rows=h("div");
  const advanced=h("input",{type:"checkbox"});
  function drawRows(){
    clear(rows);
    STAGES.forEach(function(st){
      if(STAGES.length>1)rows.append(h("div",{class:"day",style:"margin:10px 0 4px",text:st.file}));
      st.rejected.forEach(function(n){rows.append(h("div",{class:"muted",style:"font-size:12.5px"},"Skipped ",h("span",{class:"mono",text:n})," — not a usable variable name"))});
      st.entries.forEach(function(e){
        const cid=ck(st.stageId,e.key);
        const cb=h("input",{type:"checkbox",checked:CHOICE[cid].include,"aria-label":"Import "+e.key});
        cb.onchange=function(){CHOICE[cid].include=cb.checked;count()};
        const status=e.existsIn.length?h("span",{class:"badge",title:"this project already has "+e.key+" in "+e.existsIn.join(", ")},"also in "+e.existsIn.map(function(n){return setLabel("project",n)}).join(", "))
          :e.service?h("span",{class:"badge",text:e.service}):h("span");
        const r=h("div",{class:"srow"+(advanced.checked?" adv":"")},cb,h("div",{class:"k",text:e.key,title:e.key}),
          h("div",{class:"p",text:e.preview+(e.multiline?" · multi-line":"")}));
        if(advanced.checked){
          const tag=h("input",{type:"text",class:"input",placeholder:"tag",value:CHOICE[cid].note,"aria-label":"Tag for "+e.key});
          tag.oninput=function(){CHOICE[cid].note=tag.value};
          r.append(scopeSelect(cid),tag);
        }else r.append(status);
        rows.append(r);
      });
    });
  }
  const namedBox=h("div",{class:"stack"},h("div",{class:"row"},field("Save as a set called",name),field("Description (optional)",desc)),
    h("div",{class:"field"},h("span",null,"Keep it in"),dest,destHint));
  const go=h("button",{type:"button",class:"btn primary"});
  const ow=h("input",{type:"checkbox",checked:OVERWRITE,onchange:function(){OVERWRITE=ow.checked}});
  const owWrap=h("label",{class:"check",hidden:true},ow,h("span",null,"Replace keys that already exist"));
  advanced.onchange=function(){namedBox.hidden=advanced.checked;owWrap.hidden=!advanced.checked;drawRows();count()};
  function count(){
    const n=stagedCount();
    go.disabled=!n;
    go.textContent=advanced.checked?"Import "+plural(n,"key"):"Save "+plural(n,"key")+(name.value.trim()?" as “"+name.value.trim()+"”":"");
  }
  name.addEventListener("input",count);
  go.onclick=function(){advanced.checked?doImport():saveAsNamedSet(name.value.trim(),desc.value.trim(),destValue())};
  drawRows();count();
  return {
    title:"Import "+plural(total,"variable"),
    lead:"From "+files+". Nothing is saved until you choose — and values never come back to this page.",
    body:[namedBox,
      h("div",null,h("div",{class:"sechead",style:"margin:4px 0 2px"},h("h2",{style:"font-size:13.5px",text:"Variables"}),
        h("label",{class:"check",style:"font-size:13px"},advanced,h("span",null,"File them into existing sets instead"))),rows),
      owWrap],
    footer:[go],
    left:null,
  };
}

async function saveAsNamedSet(label,description,where){
  if(!label){toast("give the set a name first",{error:true});return}
  if(importing)return;importing=true;
  try{
    if(where==="library")await ensureLibrary();
    const created=await api("/api/env",{action:"create",where:where,label:label,description:description||undefined});
    const scope=created.created;
    const batches=STAGES.map(function(st){
      const assignments={};
      st.entries.forEach(function(e){const c=CHOICE[ck(st.stageId,e.key)];if(c&&c.include)assignments[e.key]={scope:scope,note:c.note||""}});
      return {stageId:st.stageId,assignments:assignments};
    }).filter(function(b){return Object.keys(b.assignments).length});
    const r=await api("/api/import",{stages:batches,where:where,overwrite:true});
    let next=r;
    next=await api("/api/link",{name:where==="library"&&scope==="default"?"library:default":scope,use:true});
    STAGES=[];CHOICE={};
    if(reviewDlg)reviewDlg.close();
    await refresh(next);
    toast("saved "+plural(r.imported.length,"key")+" as "+label+(r.vaultCreated?" — commit .hush/vault.json":""));
    location.hash=where==="library"?"#library":"#project";
  }catch(e){/* api() already said why; the review stays open */}
  finally{importing=false}
}

async function doImport(){
  if(importing)return;                       // a double click would re-send spent stages
  if(!stagedCount()){toast("nothing selected");return}
  importing=true;
  try{await runImport()}catch(err){/* leave the review open so the work is not lost */}
  finally{importing=false}
}

async function runImport(){
  const batches=STAGES.map(function(st){
    const assignments={};
    st.entries.forEach(function(e){
      const cid=ck(st.stageId,e.key);
      if(!CHOICE[cid].include)return;
      assignments[e.key]={scope:CHOICE[cid].scope,note:CHOICE[cid].note};
    });
    return {stageId:st.stageId,assignments:assignments};
  });
  const res=await api("/api/import",{stages:batches,overwrite:OVERWRITE});
  STAGES=[];CHOICE={};
  if(reviewDlg)reviewDlg.close();
  await refresh(res);
  let msg="imported "+res.imported.length;
  if(res.skipped.length)msg+=", skipped "+res.skipped.length;
  toast(res.vaultCreated?msg+" — "+VAULT_MADE:msg);
  if(res.skipped.length){
    dialog({title:"Skipped "+plural(res.skipped.length,"key"),submit:"OK",
      body:res.skipped.map(function(sk){return h("div",{class:"srow",style:"grid-template-columns:minmax(120px,200px) 1fr"},h("span",{class:"k",text:sk.key}),h("span",{class:"muted",text:sk.why}))})});
  }
  (res.unpinned||[]).forEach(function(u){
    toast(u.scope+" isn't used here, so a run won't get its "+plural(u.keys,"key"),{action:{label:"Use it here",run:function(){useHere(u.scope,u.scope,true)}}});
  });
}

/* ------------------------------------------------------------- dropping -- */

let dragDepth=0;
function dz(){return document.getElementById("drop")}
function hasFiles(ev){return ev.dataTransfer&&[].indexOf.call(ev.dataTransfer.types||[],"Files")>-1}
window.addEventListener("dragenter",function(ev){if(!hasFiles(ev))return;ev.preventDefault();dragDepth++;dz().classList.add("on")});
window.addEventListener("dragover",function(ev){if(hasFiles(ev))ev.preventDefault()});
window.addEventListener("dragleave",function(ev){if(!hasFiles(ev))return;ev.preventDefault();if(--dragDepth<=0){dragDepth=0;dz().classList.remove("on")}});
window.addEventListener("drop",function(ev){
  ev.preventDefault();dragDepth=0;dz().classList.remove("on");
  if(ev.dataTransfer&&ev.dataTransfer.files&&ev.dataTransfer.files.length)ingestFiles(ev.dataTransfer.files);
});
document.getElementById("picker").addEventListener("change",function(ev){
  if(ev.target.files&&ev.target.files.length)ingestFiles(ev.target.files);
  ev.target.value="";
});

/* ---------------------------------------------------------------- shell -- */

const SECTIONS=[["home","Home","home"],["library","Global keys","key"],["project","Project","folder"],["team","Team","team"],["agent","Agent","agent"],["activity","Activity","activity"]];
function route(){
  const r=(location.hash||"").replace("#","");
  if(r==="folder")return "project";
  if(SECTIONS.some(function(s){return s[0]===r}))return r;
  // Started inside a project: that project. Anywhere else: the list of them.
  return (CUR||(S&&S.folder.state!=="unset"))?"project":"home";
}

function navLink(id,label,ic,extra){
  const cur=route();
  return h("a",{href:"#"+id,"aria-current":cur===id?"page":null},icon(ic),h("span",{text:label}),extra||null);
}

function renderShell(){
  const here=document.getElementById("here");clear(here);
  const st=S.folder.state;
  here.append(h("div",{class:"name",text:folderName(),title:S.folder.root}),
    h("div",{class:"state"},h("span",{class:"dot "+(st==="vault"?"ok":st==="unset"?"warn":"")}),
      st==="vault"?"Encrypted in this repo":st==="links-only"?"Uses your global keys only":"Not set up"));

  const nav=document.getElementById("nav");clear(nav);
  const cur=route();
  const keyCount=S.library.reduce(function(n,x){return n+x.keys.length},0);
  nav.append(navLink("home","Home","home"),
    navLink("library","Global keys","key",keyCount?h("span",{class:"count",text:String(keyCount)}):null));

  // Every project hush knows. Click to open; drop a global key on one to give it that key.
  nav.append(h("div",{class:"navhead",text:"Projects"}));
  const here2=currentRoot();
  (HUB?HUB.projects:[]).forEach(function(p){
    const a=h("a",{href:"#project","aria-current":cur==="project"&&p.root===here2?"page":null,title:p.root,class:"proj",
      onclick:function(ev){ev.preventDefault();openProject(p.root)}},
      icon("folder"),h("span",{class:"pname",text:p.name}),h("span",{class:"count",text:String(p.keys)}));
    dropTarget(a,p);
    nav.append(a);
  });
  nav.append(h("button",{type:"button",class:"navadd",onclick:addFolderDialog},icon("plus"),"Add a folder"));

  // What the rest applies to: the project on screen.
  nav.append(h("div",{class:"navhead",text:folderName()}));
  const win=S.folder.state==="unset"?{}:winners();
  const missing=(S.needs||[]).filter(function(n){return !win[n.name]}).length;
  nav.append(navLink("project","Keys here","folder",missing&&S.folder.state!=="unset"?h("span",{class:"count warn",title:missing+" credentials the code reads are missing",text:missing+" missing"}):null),
    navLink("team","Team","team",S.members.length?h("span",{class:"count",text:String(S.members.length)}):null),
    navLink("agent","Agent","agent"),
    navLink("activity","Activity","activity"));

  const lv=document.getElementById("level");clear(lv);
  const meter=h("div",{class:"meter"});
  for(let i=1;i<=5;i++)meter.append(h("i",{class:i<=S.posture.rung?"on":""}));
  lv.append(h("div",{class:"t"},h("span",null,"Protection"),h("b",{text:S.posture.rung+" of 5"})),meter);
  lv.setAttribute("aria-label","Protection level "+S.posture.rung+" of 5 — see the Agent section");
}

/* --------------------------------------------------------------- home */

function addFolderDialog(){
  const path=h("input",{class:"input mono",placeholder:"/Users/you/code/my-app",autocomplete:"off",spellcheck:"false"});
  dialog({title:"Add a project",lead:"A folder hush already works in (it has a .hush folder). To start hush in a new one, run hush in it once.",
    submit:"Add",body:[field("Folder",path)],
    onSubmit:async function(){
      if(!path.value.trim()){path.focus();return false}
      HUB=await api("/api/projects",{action:"add",root:path.value.trim()});
      render();toast("added");
    }});
}

function renderHome(page){
  page.append(h("header",{class:"head"},
    h("div",null,h("h1",null,"Your projects"),
      h("p",{text:"Every project hush knows on this machine. Drag a global key onto a project — here or in the sidebar — to make it part of that project. It stays yours: nothing goes into the project's repository."})),
    h("div",{class:"actions"},
      h("button",{type:"button",class:"btn",onclick:addFolderDialog},icon("plus"),"Add a folder"),
      h("button",{type:"button",class:"btn primary",onclick:function(){addSecretDialog({target:"library|default"})}},icon("key"),"Save a global key"))));

  const projects=HUB?HUB.projects:[];
  if(!projects.length){
    page.append(h("div",{class:"card"},h("div",{class:"empty"},h("h3",null,"No projects yet"),
      h("p",{text:"Run hush in a project once (hush setup, hush run, anything) and it shows up here. Or add a folder that already has a .hush folder."}),
      h("div",{class:"actions"},h("button",{type:"button",class:"btn primary",onclick:addFolderDialog},icon("plus"),"Add a folder")))));
  }else{
    const grid=h("div",{class:"pgrid"});
    projects.forEach(function(p){
      const card=h("button",{type:"button",class:"pcard",onclick:function(){openProject(p.root)}},
        h("div",{class:"ptop"},icon("folder"),h("b",{text:p.name})),
        h("div",{class:"mono pdir",text:tildePath(p.root)}),
        h("div",{class:"pmeta"},
          h("span",{class:"badge"+(p.keys?" ok":""),text:plural(p.keys,"key")}),
          p.fromGlobal?h("span",{class:"muted",text:p.fromGlobal+" from your global keys"}):null,
          h("span",{class:"muted",text:p.state==="vault"?"· own vault":"· global keys only"})));
      dropTarget(card,p);
      grid.append(card);
    });
    page.append(grid);
  }

  // Your global keys, ready to drag, without leaving the page.
  const chips=h("div",{class:"chips"});
  S.library.forEach(function(set){
    set.keys.forEach(function(k){
      const c=h("span",{class:"chip",title:"From "+set.label+" — drag onto a project"},icon("grip"),h("span",{class:"mono",text:k}),
        set.name!=="default"?h("small",{text:set.label}):null);
      draggableKey(c,set.name,k);
      chips.append(c);
    });
  });
  page.append(h("section",{class:"section"},
    h("div",{class:"sechead"},h("div",null,h("h2",{text:"Global keys"}),
      h("p",{text:S.library.length?"Drag any of these onto a project.":"Keys you keep once and use in any project. Save one to start."}))),
    S.library.length?chips:null));
}

function render(){
  if(!S)return;
  closeMenu();
  renderShell();
  const page=document.getElementById("page");clear(page);
  const r=route();
  // A vault that changed without anyone here accepting it: nothing in it is
  // decrypted, and the way out is a terminal command, on every section.
  if(S.trust&&S.trust.length){
    const lines=h("div",null);
    S.trust.forEach(function(l,i){lines.append(h(i===0?"b":"div",{text:l}))});
    page.append(h("div",{class:"banner warn",role:"alert",style:"margin-bottom:14px"},icon("alert"),lines));
  }
  if(r==="home")renderHome(page);
  else if(r==="project")renderProject(page);
  else if(r==="library")renderLibrary(page);
  else if(r==="team")renderTeam(page);
  else if(r==="agent")renderAgent(page);
  else renderActivity(page);
  document.title=(r==="project"?folderName():SECTIONS.find(function(s){return s[0]===r})[1])+" · hush";
}
window.addEventListener("hashchange",function(){if(route()==="activity")AUDIT=null;render();window.scrollTo(0,0)});

refresh().catch(function(e){
  const page=document.getElementById("page");clear(page);
  // No token, or one from a previous run: the only fix is the link this run printed.
  const noToken=!T||/bad token/.test(e.message);
  page.append(h("div",{class:"card"},h("div",{class:"empty"},
    h("h3",null,noToken?"Open the link hush printed":"Couldn't load"),
    h("p",{text:noToken?"This page needs the one-time link from the terminal where you ran hush ui. Each run prints a new one.":e.message}))));
});
</script></body></html>`;
