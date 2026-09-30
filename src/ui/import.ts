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

const SECTIONS=[["project","Project","folder"],["library","Library","library"],["team","Team","team"],["agent","Agent","agent"],["activity","Activity","activity"]];
function route(){
  const r=(location.hash||"").replace("#","");
  if(r==="folder")return "project";
  return SECTIONS.some(function(s){return s[0]===r})?r:"project";
}

function renderShell(){
  const here=document.getElementById("here");clear(here);
  const st=S.folder.state;
  here.append(h("div",{class:"name",text:folderName(),title:S.folder.root}),
    h("div",{class:"state"},h("span",{class:"dot "+(st==="vault"?"ok":st==="unset"?"warn":"")}),
      st==="vault"?"Encrypted in this repo":st==="links-only"?"Uses your library only":"Not set up"));

  const win=S.folder.state==="unset"?{}:winners();
  const missing=(S.needs||[]).filter(function(n){return !win[n.name]}).length;
  const counts={project:S.folder.state==="unset"?0:missing,library:S.library.length,team:S.members.length};
  const nav=document.getElementById("nav");clear(nav);
  const cur=route();
  SECTIONS.forEach(function(s){
    const c=counts[s[0]];
    nav.append(h("a",{href:"#"+s[0],"aria-current":cur===s[0]?"page":null},icon(s[2]),h("span",{text:s[1]}),
      c?h("span",{class:"count"+(s[0]==="project"?" warn":""),title:s[0]==="project"?c+" variables the code reads are missing":null,text:s[0]==="project"?c+" missing":String(c)}):null));
  });

  const lv=document.getElementById("level");clear(lv);
  const meter=h("div",{class:"meter"});
  for(let i=1;i<=5;i++)meter.append(h("i",{class:i<=S.posture.rung?"on":""}));
  lv.append(h("div",{class:"t"},h("span",null,"Protection"),h("b",{text:S.posture.rung+" of 5"})),meter);
  lv.setAttribute("aria-label","Protection level "+S.posture.rung+" of 5 — see the Agent section");
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
  if(r==="project")renderProject(page);
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
