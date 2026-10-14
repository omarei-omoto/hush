/**
 * The frame around every section: the left sidebar (Home, Global keys, and
 * your projects in their groups), a project's header and its tabs (Keys,
 * Team, Agent, Activity), Home's views of the project list, and the
 * Suggested lists — each suggestion with the one click that does it.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const VIEWS = String.raw`
/* ---------------------------------------------------------------- routes -- */

const SECTIONS=[["home","Home","home"],["library","Global keys","key"],["project","Keys","folder"],["team","Team","team"],["agent","Agent","agent"],["activity","Activity","activity"]];
/* A project's tabs: each is about the project on screen. */
const PROJECT_TABS=["project","team","agent","activity"];
function route(){
  const r=(location.hash||"").replace("#","");
  if(r==="folder")return "project";
  if(SECTIONS.some(function(s){return s[0]===r}))return r;
  // Started inside a project: that project. Anywhere else: the list of them.
  return (CUR||(S&&S.folder.state!=="unset"))?"project":"home";
}
function navLink(id,label,ic,extra){
  return h("a",{href:"#"+id,"aria-current":route()===id?"page":null},icon(ic),h("span",{text:label}),extra||null);
}

/* A view setting, kept per browser; a page that cannot store one still works. */
function pref(name,dflt){try{const v=localStorage.getItem("hush-"+name);return v===null?dflt:JSON.parse(v)}catch(e){return dflt}}
function setPref(name,v){try{localStorage.setItem("hush-"+name,JSON.stringify(v))}catch(e){}}

/* ----------------------------------------------------------- the sidebar -- */

let SIDE_SHUT=pref("side-shut",[]);

/** Projects by their group: {groups:[{label,items}], loose:[…]}. */
function byGroup(list){
  const map={};const order=[];
  list.forEach(function(p){if(!p.group)return;if(!map[p.group]){map[p.group]=[];order.push(p.group)}map[p.group].push(p)});
  order.sort(function(a,b){return a.localeCompare(b)});
  return {groups:order.map(function(k){return {label:k,items:map[k]}}),loose:list.filter(function(p){return !p.group})};
}

function renderShell(){
  const nav=document.getElementById("nav");clear(nav);
  const cur=route();
  const onProject=PROJECT_TABS.indexOf(cur)>-1;
  const keyCount=globalSets().reduce(function(n,x){return n+x.keys.length},0);
  nav.append(navLink("home","Home","home"),
    navLink("library","Global keys","key",keyCount?h("span",{class:"count",text:String(keyCount)}):null),
    // On a phone the bar holds the sections; the project on screen is one of them.
    h("a",{href:"#project",class:"phone","aria-current":onProject?"page":null},icon("folder"),h("span",{text:folderName()})));
  nav.append(h("div",{class:"navhead"},h("span",{text:"Projects"}),
    h("button",{type:"button",class:"iconbtn","aria-label":"Add a folder",title:"Add a folder",onclick:addFolderDialog},icon("plus"))));
  const here=currentRoot();
  // Projects using hush, the one on screen, and any you filed in a group.
  const all=(HUB?HUB.projects:[]).filter(function(p){return p.state!=="codebase"||p.group||p.root===here});
  const by=byGroup(all);
  by.groups.forEach(function(g){
    const shut=SIDE_SHUT.indexOf(g.label)>-1;
    const head=h("div",{class:"pgroup"+(shut&&onProject&&g.items.some(function(p){return p.root===here})?" holds":"")},
      h("button",{type:"button",class:"fold","aria-expanded":String(!shut),onclick:function(){
        SIDE_SHUT=shut?SIDE_SHUT.filter(function(x){return x!==g.label}):SIDE_SHUT.concat([g.label]);setPref("side-shut",SIDE_SHUT);renderShell();
      }},icon(shut?"right":"down"),h("span",{class:"pname",text:g.label})),
      h("span",{class:"count",text:String(g.items.length)}),
      moreButton("More for "+g.label,function(){return projectGroupMenu(g)}));
    groupDrop(head,g);
    nav.append(head);
    if(!shut)g.items.forEach(function(p){nav.append(projectRow(p,onProject&&p.root===here,true))});
  });
  by.loose.forEach(function(p){nav.append(projectRow(p,onProject&&p.root===here,false))});
  if(!all.length)nav.append(h("p",{class:"navnote",text:"None yet — Home lists every codebase hush found."}));
}

function projectRow(p,current,inGroup){
  const lacking=p.state!=="codebase"&&p.lacking&&p.lacking.length;
  const a=h("a",{href:"#project","aria-current":current?"page":null,title:p.root,class:"proj"+(inGroup?" ingroup":""),"data-root":p.root,
    onclick:function(ev){ev.preventDefault();openProject(p.root)}},
    h("span",{class:"pname",text:p.name}),
    lacking?h("span",{class:"dot warn",title:plural(p.lacking.length,"key")+" its code reads "+(p.lacking.length===1?"is":"are")+" missing: "+p.lacking.join(", ")}):null,
    h("span",{class:"count",text:p.state==="codebase"?"":String(p.keys)}));
  dropTarget(a,p);
  draggableProject(a,p);
  return h("div",{class:"projrow"},a,projectMenu(p));
}

/* ------------------------------------------------------- project groups -- */

const PROJECT_MIME="application/x-hush-project";
/** A project you can drag onto a group, in the sidebar or on Home. */
function draggableProject(el,p){
  el.draggable=true;
  el.addEventListener("dragstart",function(ev){
    ev.dataTransfer.setData(PROJECT_MIME,p.root);
    ev.dataTransfer.setData("text/plain",p.name);
    ev.dataTransfer.effectAllowed="move";
    document.body.classList.add("dragging-project");
  });
  el.addEventListener("dragend",function(){document.body.classList.remove("dragging-project");clearDragMarks()});
}
/** A group takes a project (filed under it) or something global (given to every project in it). */
function groupDrop(el,g){
  el.addEventListener("dragover",function(ev){
    const t=[].slice.call(ev.dataTransfer.types||[]);
    if(t.indexOf(KEY_MIME)<0&&t.indexOf(PROJECT_MIME)<0)return;
    ev.preventDefault();el.classList.add("drop-on");
  });
  el.addEventListener("dragleave",function(ev){if(!el.contains(ev.relatedTarget))el.classList.remove("drop-on")});
  el.addEventListener("drop",async function(ev){
    el.classList.remove("drop-on");
    const root=ev.dataTransfer.getData(PROJECT_MIME);
    const raw=ev.dataTransfer.getData(KEY_MIME);
    if(!root&&!raw)return;
    ev.preventDefault();ev.stopPropagation();
    if(root){await fileProjects([root],g.label);return}
    giveGroup(g,JSON.parse(raw));
  });
}
async function fileProjects(roots,label){
  HUB=await api("/api/projects",{action:"group",roots:roots,group:label||null});
  SUG=null;render();
  toast(label?plural(roots.length,"project")+" in "+label:"out of its group");
}
/** Give one global key, set or group to every project in a project group. */
async function giveGroup(g,what){
  let r=null,n=0;
  for(const p of g.items){r=await api("/api/assign",{project:p.root,kind:what.kind,set:what.set,key:what.key,group:what.group});if(r.assigned==="added")n++}
  if(r)HUB=r;
  toast(n?giveName(what)+" is now part of "+plural(n,"project")+" in "+g.label:"every project in "+g.label+" already gets "+giveName(what));
  if(g.items.some(function(p){return p.root===currentRoot()}))await refresh();else{SUG=null;render()}
}
function projectGroupMenu(g){
  return [
    {label:"Rename…",run:function(){
      const name=h("input",{class:"input",value:g.label});
      dialog({title:"Rename "+g.label,submit:"Rename",body:[field("Name",name)],onSubmit:async function(){
        if(!name.value.trim()){name.focus();return false}
        HUB=await api("/api/projects",{action:"rename-group",group:g.label,label:name.value.trim()});render();toast("renamed");
      }});
    }},
    {label:"Ungroup",run:async function(){HUB=await api("/api/projects",{action:"ungroup",group:g.label});render();toast(g.label+" is ungrouped — its projects are still listed")}},
  ];
}
/** File one project under a group: one there is, a new one, or none. */
function projectGroupDialog(p){
  const groups=(HUB&&HUB.groups)||[];
  const sel=h("select",{class:"input"});
  sel.append(h("option",{value:"",text:"No group"}));
  groups.forEach(function(g){sel.append(h("option",{value:g.label},g.label))});
  sel.append(h("option",{value:"\u0000new",text:"New group…"}));
  sel.value=p.group||(groups[0]?groups[0].label:"\u0000new");
  const name=h("input",{class:"input",placeholder:"e.g. Clients"});
  const wrap=field("New group's name",name);
  function sync(){wrap.hidden=sel.value!=="\u0000new"}
  sel.onchange=sync;sync();
  dialog({title:"Put "+p.name+" in a group",lead:"Groups keep the project list tidy. Drag a global key onto a group and every project in it gets it.",
    submit:"Save",body:[field("Group",sel),wrap],
    onSubmit:async function(){
      const label=sel.value==="\u0000new"?name.value.trim():sel.value;
      if(sel.value==="\u0000new"&&!label){toast("name the group",{error:true});name.focus();return false}
      await fileProjects([p.root],label);
    }});
}

/* ----------------------------------------------- a project's header, tabs -- */

/** The project on screen, as the list knows it (its group, branch, counts). */
function hubProject(){
  const root=currentRoot();
  return (HUB?HUB.projects:[]).find(function(p){return p.root===root})||{root:root,name:folderName(),state:S.folder.state==="unset"?"codebase":S.folder.state,keys:0,lacking:[]};
}
function projectHeader(page,tab){
  const name=folderName();
  const st=S.folder.state;
  const hp=hubProject();
  const win=st==="unset"?{}:winners();
  const missing=(S.needs||[]).filter(function(n){return !win[n.name]});
  const health=h("div",{class:"health"});
  if(st==="unset")health.append(h("span",{class:"badge"},"Not set up"));
  else{
    health.append(h("span",{text:plural(Object.keys(win).length,"key")}));
    if(missing.length)health.append(h("a",{href:"#project",class:"warn",text:missing.length+" missing"}));
    const o=S.onboarding;
    if(o&&o.next)health.append(h("span",{text:"setup "+o.done+" of "+o.total}));
  }
  health.append(h("a",{href:"#agent",title:"How well this project's keys are kept from an agent and from other software — see Agent"},"protection "+S.posture.rung+" of 5"));
  const tabs=h("nav",{class:"tabs","aria-label":name},
    [["project","Keys"],["team","Team"],["agent","Agent"],["activity","Activity"]].map(function(t){
      return h("a",{href:"#"+t[0],"aria-current":tab===t[0]?"page":null},t[1],
        t[0]==="team"&&S.members.length>1?h("span",{class:"count",text:String(S.members.length)}):null);
    }));
  page.append(h("header",{class:"head phead"},
    h("div",{class:"ptitle"},
      h("div",{class:"pline"},h("h1",{text:name}),hp.group?h("span",{class:"badge"},icon("folder"),hp.group):null),
      h("div",{class:"meta"},h("span",{class:"mono",title:S.folder.root,text:tildePath(S.folder.root)+(hp.branch?" · "+hp.branch:"")}),health)),
    h("div",{class:"actions"},
      st==="unset"?null:addMenuButton(),
      moreButton("More for "+name,function(){return projectMenuItems(hp).filter(function(it){return it==="-"||it.label!=="Open"})}))),
    tabs);
}
function addMenuButton(){
  const b=h("button",{type:"button",class:"btn primary","aria-haspopup":"menu"},icon("plus"),"Add");
  b.onclick=function(){menu(b,[
    {label:"A key…",run:function(){addSecretDialog()}},
    {label:"Import a .env…",run:function(){DROP_WHERE="own";document.getElementById("picker").click()}},
    {label:"A set for "+folderName()+" only…",run:function(){newSetDialog("own")}},
    {label:"A global set…",run:function(){newSetDialog("library")}},
  ])};
  return b;
}

/* ------------------------------------------------------------ suggestions -- */

/* What suggest.ts offers: null until asked, then the list. Asked again after any change. */
let SUG=null;
function loadSuggestions(){
  if(SUG!==null)return;
  SUG="asking";
  api("/api/suggestions",{}).then(function(r){SUG=r.suggestions;if(SUG.length)render()},function(){SUG=[]});
}
const SUG_ICON={give:"key","same-value":"copy",plaintext:"alert","only-one":"folder",replace:"lock",repush:"arrowup",group:"folder"};
/** Suggestions about one project (root), of some kinds, or all of them; null when there are none. */
function suggestionsCard(root,kinds,title){
  loadSuggestions();
  if(!Array.isArray(SUG))return null;
  const list=SUG.filter(function(s){return (!root||s.roots.indexOf(root)>-1)&&(!kinds||kinds.indexOf(s.kind)>-1)});
  if(!list.length)return null;
  const LIMIT=3;
  const card=h("section",{class:"card sugg","aria-label":"Suggested"},
    h("div",{class:"sughead"},icon("spark"),h("b",{text:title||"Suggested"}),h("span",{class:"count",text:String(list.length)})));
  list.forEach(function(s,i){card.append(suggestionRow(s,i>=LIMIT))});
  if(list.length>LIMIT){
    card.append(h("button",{type:"button",class:"linkbtn more",onclick:function(ev){
      [].forEach.call(card.querySelectorAll(".sug[hidden]"),function(x){x.hidden=false});ev.currentTarget.remove()}},"Show "+(list.length-LIMIT)+" more"));
  }
  return card;
}
function suggestionRow(s,hidden){
  return h("div",{class:"sug",hidden:hidden},icon(SUG_ICON[s.kind]||"info"),h("span",{class:"stext",text:s.text}),
    h("button",{type:"button",class:"btn sm",onclick:function(ev){runSuggestion(s,ev.currentTarget)}},s.label),
    h("button",{type:"button",class:"iconbtn","aria-label":"Don't suggest this again",title:"Don't suggest this again",onclick:function(){dismissSuggestion(s)}},icon("x")));
}
async function dismissSuggestion(s){
  await api("/api/suggestions",{action:"dismiss",id:s.id});
  if(Array.isArray(SUG))SUG=SUG.filter(function(x){return x.id!==s.id});
  render();
}
async function runSuggestion(s,btn){
  const a=s.act;
  if(btn)btn.disabled=true;
  try{
    if(a.assign){
      let r=null;
      for(const it of a.assign.items)r=await api("/api/assign",Object.assign({project:a.assign.project},it));
      if(r)HUB=r;
      toast(s.names[0]+" has it now");
      if(a.assign.project===currentRoot())await refresh();else{SUG=null;render()}
    }else if(a.share){await placed(await api("/api/share",a.share))}
    else if(a.tidy){const r=await api("/api/tidy",{action:"apply",picks:[a.tidy]});await refresh(r);toast(r.done[0]||"done")}
    else if(a.group){await fileProjects(a.group.roots,a.group.label)}
    else if(a.replace){replaceDialog(a.replace.where,a.replace.set,a.replace.key)}
    else if(a.importEnv){await importEnvOf(a.importEnv.project)}
    else if(a.repush){
      const x=a.repush;
      if(x.project!==currentRoot()){setProject(x.project);location.hash="#project";await refresh()}
      const r=await api("/api/push",{where:x.where,set:x.set,key:x.key,to:x.to,target:x.target,env:x.env,as:x.as});
      await refresh(r);toast(r.done,r.ok?null:{error:true});
      if(!r.ok&&r.output&&r.output.trim())cliOutputDialog(x.to,r.output);
    }
  }finally{if(btn&&btn.isConnected)btn.disabled=false}
}
/* The .env sitting in a project's folder, read by the hush server and reviewed like a dropped one. */
let IMPORT_FROM_DISK=null;
async function importEnvOf(root){
  if(root!==currentRoot()){setProject(root);location.hash="#project";await refresh()}
  const st=await api("/api/stage-file",{});
  if(!st.entries.length&&!st.rejected.length){toast("its .env has no variables in it");return}
  STAGES.push(st);
  st.entries.forEach(function(e){CHOICE[ck(st.stageId,e.key)]={scope:e.suggestedScope,note:e.service||"",include:true}});
  IMPORT_FROM_DISK=folderName();
  DROP_WHERE="own";
  openReview();
}
/* Said once a file read from disk is saved: the plaintext copy is still there. */
function afterDiskImport(){
  if(!IMPORT_FROM_DISK)return;
  toast("saved — now delete "+IMPORT_FROM_DISK+"/.env: hush has the values, and a plaintext copy is what leaks");
  IMPORT_FROM_DISK=null;
}

/* ----------------------------------------------------------------- home -- */

/* Pick a folder with the system's own picker (Finder on a Mac), opened by the
   hush server: a browser page cannot hand a server a folder's path. */
async function pickFolder(purpose){return await api("/api/pick-folder",{purpose:purpose})}
/* field is the path box beside it: where to type when there is no picker. */
function chooseButton(purpose,label,then,cls,field){
  const b=h("button",{type:"button",class:"btn "+(cls||"sm")},icon("folder"),label||"Choose a folder…");
  b.onclick=async function(){
    b.disabled=true;
    try{
      const r=await pickFolder(purpose);
      if(r.path)await then(r.path);
      else if(r.picker===false){
        toast("No folder picker on this system (on Linux, install zenity or kdialog) — paste the path instead",{error:true});
        if(field)field.focus();
      }
    }
    finally{b.disabled=false}
  };
  return b;
}
function addFolderDialog(){
  const path=h("input",{class:"input mono",placeholder:"/Users/you/code/my-app",autocomplete:"off",spellcheck:"false",style:"flex:1;min-width:0"});
  const choose=chooseButton("project","Choose…",function(p){path.value=p},"sm",path);
  dialog({title:"Add a project",lead:"Any codebase: a git repository, or a folder with a package.json, pyproject.toml or the like. Pick it, or paste its path.",
    submit:"Add",body:[field("Folder",h("div",{class:"row",style:"gap:8px;align-items:center;flex-wrap:nowrap"},path,choose))],
    onSubmit:async function(){
      if(!path.value.trim()){path.focus();return false}
      HUB=await api("/api/projects",{action:"add",root:path.value.trim()});
      render();toast("added");
    }});
}

function ago(iso){
  if(!iso)return "";
  const d=(Date.now()-Date.parse(iso))/1000;
  if(d<3600)return Math.max(1,Math.round(d/60))+"m ago";
  if(d<86400)return Math.round(d/3600)+"h ago";
  if(d<86400*45)return Math.round(d/86400)+"d ago";
  return Math.round(d/86400/30)+"mo ago";
}

/* While a crawl runs, Home refreshes itself so the list fills in as it goes. */
let CRAWL_TIMER=null;
function watchCrawl(){
  clearTimeout(CRAWL_TIMER);
  if(!HUB||!HUB.crawl||!HUB.crawl.running)return;
  CRAWL_TIMER=setTimeout(async function(){
    try{await reloadHub()}catch(e){return}
    if(route()==="home"&&!document.querySelector("dialog[open]"))render();else renderShell();
    watchCrawl();
  },1200);
}

/* Where hush looks for codebases: one line on Home; the list itself in a dialog. */
function lookingLine(){
  const c=HUB.crawl||{};
  const roots=(HUB.roots||[]).map(tildePath);
  return h("div",{class:"looking"},
    h("span",{text:c.running
      ?"Looking for codebases… "+c.done+" of "+c.total
      :(roots.length?"Looking in "+roots.join(", "):"Not looking in any folder")+(HUB.rootsChosen?"":" (your usual code folders)")+(c.finished?" · last looked "+ago(c.finished):"")}),
    c.running?h("span",{class:"progress inline"},h("i",{style:"width:"+Math.round(100*c.done/Math.max(1,c.total))+"%"})):null,
    h("button",{type:"button",class:"linkbtn",disabled:!!c.running,onclick:async function(){HUB=await api("/api/crawl",{});render();watchCrawl()}},"Look again"),
    h("button",{type:"button",class:"linkbtn",onclick:foldersDialog},"Change folders…"));
}
function foldersDialog(){
  const box=h("div",{class:"stack"});
  function draw(){
    clear(box);
    const list=h("div",{class:"chips"});
    (HUB.roots||[]).forEach(function(r){
      list.append(h("span",{class:"chip"},icon("folder"),h("span",{class:"mono",text:tildePath(r)}),
        h("button",{type:"button",class:"iconbtn","aria-label":"Stop looking in "+r,onclick:async function(){
          HUB=await api("/api/crawl",{roots:HUB.roots.filter(function(x){return x!==r})});draw();render();watchCrawl();
        }},icon("x"))));
    });
    const lookIn=async function(p){HUB=await api("/api/crawl",{roots:(HUB.roots||[]).concat([p])});draw();render();watchCrawl()};
    const input=h("input",{class:"input mono",placeholder:"or paste a path: ~/code",autocomplete:"off",spellcheck:"false",style:"flex:1;min-width:0"});
    const f=h("form",{class:"row",style:"gap:8px;align-items:center;flex-wrap:wrap"},
      chooseButton("roots","Choose a folder…",lookIn,"sm primary",input),input,h("button",{type:"submit",class:"btn sm"},icon("plus"),"Add"));
    f.onsubmit=async function(ev){ev.preventDefault();ev.stopPropagation();if(!input.value.trim()){input.focus();return}await lookIn(input.value.trim())};
    box.append(list,f);
  }
  draw();
  dialog({title:"Folders hush looks in",lead:"Every codebase in them is listed on Home, with its stack and the credentials its code reads — names only, never a value.",
    noSubmit:true,cancel:"Done",body:[box]});
}

/* How Home shows the list, kept per browser. */
let HOME=Object.assign({view:"grid",by:"group",sort:"recent",show:"all"},pref("home",{}));
let HOME_QUERY="";
function setHome(k,v){HOME[k]=v;setPref("home",HOME);render()}

/** Something about it needs you: a credential its code reads is missing, a plaintext .env, or a suggestion about it. */
function needsYou(p){
  if(p.state!=="codebase"&&p.lacking&&p.lacking.length)return true;
  if(p.plaintextEnv)return true;
  return Array.isArray(SUG)&&SUG.some(function(s){return s.kind!=="group"&&s.roots.indexOf(p.root)>-1});
}
function matches(p,q){
  if(!q)return true;
  return [p.name,p.root,(p.stack||[]).join(" "),p.branch||"",p.group||""].join(" ").toLowerCase().indexOf(q)>-1;
}

function renderHome(page){
  page.append(h("header",{class:"head"},
    h("div",null,h("h1",null,"Projects"),
      h("p",{text:"Every codebase hush found or was used in. Drag a global key, set or group from the right onto one — it stays yours, and nothing goes into the repository."})),
    h("div",{class:"actions"},h("button",{type:"button",class:"btn",onclick:addFolderDialog},icon("plus"),"Add a folder"))));
  page.append(lookingLine());
  add(page,suggestionsCard(null,null));
  const projects=HUB?HUB.projects:[];
  if(!projects.length){
    page.append(h("div",{class:"card"},h("div",{class:"empty"},h("h3",null,HUB&&HUB.crawl&&HUB.crawl.running?"Looking for codebases…":"No codebases found yet"),
      h("p",{text:"Change the folders hush looks in, or add one project by hand."}))));
  }else{
    const box=h("div");
    page.append(homeToolbar(projects,box),box);
    fillProjects(box,projects);
  }
  add(page,hiddenSection());
  watchCrawl();
}

function homeToolbar(projects,box){
  const bar=h("div",{class:"toolbar"});
  const q=h("input",{class:"input",type:"search",placeholder:"Filter",value:HOME_QUERY,"aria-label":"Filter projects by name, folder, stack or group",autocomplete:"off",spellcheck:"false"});
  q.addEventListener("input",function(){HOME_QUERY=q.value;fillProjects(box,projects)});
  const shows=[["all","All",projects.length],["attention","Needs you",projects.filter(needsYou).length],
    ["hush","Using hush",projects.filter(function(p){return p.state!=="codebase"}).length],["fresh","Not set up",projects.filter(function(p){return p.state==="codebase"}).length]];
  const chips=h("div",{class:"seg chips-f",role:"radiogroup","aria-label":"Show"});
  shows.forEach(function(s){
    if(s[0]!=="all"&&!s[2])return;
    chips.append(h("button",{type:"button",role:"radio","aria-checked":String(HOME.show===s[0]),class:HOME.show===s[0]?"on":"",onclick:function(){setHome("show",s[0])}},s[1],h("span",{class:"count",text:String(s[2])})));
  });
  const by=h("select",{class:"input sm","aria-label":"Group by"},
    h("option",{value:"group"},"By group"),h("option",{value:"folder"},"By folder"),h("option",{value:"none"},"No grouping"));
  by.value=HOME.by;by.onchange=function(){setHome("by",by.value)};
  const sort=h("select",{class:"input sm","aria-label":"Sort"},
    h("option",{value:"recent"},"Recent first"),h("option",{value:"name"},"By name"),h("option",{value:"attention"},"Needs you first"));
  sort.value=HOME.sort;sort.onchange=function(){setHome("sort",sort.value)};
  const view=h("div",{class:"seg views",role:"radiogroup","aria-label":"View"},
    h("button",{type:"button",role:"radio","aria-checked":String(HOME.view==="grid"),class:HOME.view==="grid"?"on":"","aria-label":"Cards",title:"Cards",onclick:function(){setHome("view","grid")}},icon("grid")),
    h("button",{type:"button",role:"radio","aria-checked":String(HOME.view==="list"),class:HOME.view==="list"?"on":"","aria-label":"List",title:"List",onclick:function(){setHome("view","list")}},icon("list")));
  bar.append(q,chips,h("div",{class:"tright"},by,sort,view));
  return bar;
}

function fillProjects(box,projects){
  clear(box);
  const q=HOME_QUERY.trim().toLowerCase();
  let shown=projects.filter(function(p){
    if(!matches(p,q))return false;
    if(HOME.show==="attention")return needsYou(p);
    if(HOME.show==="hush")return p.state!=="codebase";
    if(HOME.show==="fresh")return p.state==="codebase";
    return true;
  });
  const when=function(p){return p.active||""};
  shown=shown.slice().sort(function(a,b){
    if(HOME.sort==="name")return a.name.localeCompare(b.name);
    if(HOME.sort==="attention"&&needsYou(a)!==needsYou(b))return needsYou(a)?-1:1;
    return when(b).localeCompare(when(a))||a.name.localeCompare(b.name);
  });
  if(!shown.length){box.append(h("p",{class:"muted",style:"margin-top:18px",text:q?"No project matches “"+HOME_QUERY.trim()+"”.":"Nothing here."}));return}
  const sections=[];
  if(HOME.by==="group"){
    const by=byGroup(shown);
    by.groups.forEach(function(g){sections.push({title:g.label,items:g.items,group:g})});
    const setUp=by.loose.filter(function(p){return p.state!=="codebase"});
    const fresh=by.loose.filter(function(p){return p.state==="codebase"});
    if(setUp.length)sections.push({title:by.groups.length?"No group":"Using hush",items:setUp});
    // Codebases nobody set up wait, folded, unless they are what you asked to see.
    if(fresh.length)sections.push({title:"Not set up",items:fresh,folded:HOME.show!=="fresh"&&!q&&(setUp.length+by.groups.length)>0,
      note:"Found in your folders. Drop a global key on one to set it up with that key, or hide one that isn't yours from its ⋯ menu."});
  }else if(HOME.by==="folder"){
    const map={};const order=[];
    shown.forEach(function(p){const d=tildePath(p.root.replace(/[\\/][^\\/]+$/,""));if(!map[d]){map[d]=[];order.push(d)}map[d].push(p)});
    order.sort().forEach(function(d){sections.push({title:d,items:map[d],mono:true})});
  }else sections.push({title:"",items:shown});
  sections.forEach(function(sec){box.append(projectSection(sec))});
}

function projectSection(sec){
  const items=HOME.view==="list"?h("div",{class:"card plist"}):h("div",{class:"pgrid"});
  sec.items.forEach(function(p){items.append(HOME.view==="list"?projectListRow(p):projectCard(p))});
  if(!sec.title)return h("section",{class:"section"},items);
  const head=h("summary",null,sec.group?icon("folder"):null,h("span",{class:sec.mono?"mono":"",text:sec.title}),h("span",{class:"count",text:String(sec.items.length)}),
    sec.group?h("span",{class:"tright"},moreButton("More for "+sec.title,function(){return projectGroupMenu(sec.group)})):null);
  if(sec.group)groupDrop(head,sec.group);
  const d=h("details",{class:"section psec",open:!sec.folded},head,sec.note?h("p",{class:"muted",text:sec.note}):null,items);
  return d;
}

function projectCard(p){
  const lacking=p.state!=="codebase"&&p.lacking?p.lacking:[];
  // The name is the link, stretched over the whole card; the menu sits above it.
  const card=h("div",{class:"pcard"+(p.state==="codebase"?" fresh":""),title:p.root,"data-root":p.root},
    h("div",{class:"ptop"},
      h("a",{href:"#project",class:"pcover",onclick:function(ev){ev.preventDefault();openProject(p.root)}},h("b",{text:p.name})),
      h("span",{class:"pend"},p.active?h("span",{class:"muted ago",text:ago(p.active)}):null,projectMenu(p))),
    h("div",{class:"mono pdir",text:tildePath(p.root)+(p.branch?" · "+p.branch:"")}),
    h("div",{class:"pmeta"},
      (p.stack||[]).slice(0,2).map(function(t){return h("span",{class:"tech",text:t})}),
      p.state==="codebase"
        ?h("span",{class:"muted",text:p.credentials&&p.credentials.length?"reads "+plural(p.credentials.length,"credential"):"not set up"})
        :h("span",{class:"badge"+(p.keys?" ok":""),text:plural(p.keys,"key")}),
      lacking.length?h("span",{class:"badge warn",title:lacking.join(", "),text:lacking.length+" missing"}):null,
      p.plaintextEnv?h("span",{class:"badge warn",title:"A .env with values in it sits in this folder",text:".env"}):null));
  dropTarget(card,p);
  draggableProject(card,p);
  return card;
}
function projectListRow(p){
  const lacking=p.state!=="codebase"&&p.lacking?p.lacking:[];
  const row=h("div",{class:"prow",title:p.root,"data-root":p.root},
    h("a",{href:"#project",class:"pcover",onclick:function(ev){ev.preventDefault();openProject(p.root)}},h("b",{text:p.name})),
    h("span",{class:"muted",text:(p.stack||[]).slice(0,2).join(" · ")}),
    h("span",{class:"mono muted pdir",text:tildePath(p.root)}),
    h("span",{class:"pmeta"},
      p.state==="codebase"?h("span",{class:"muted",text:"not set up"}):h("span",{class:"badge"+(p.keys?" ok":""),text:plural(p.keys,"key")}),
      lacking.length?h("span",{class:"badge warn",title:lacking.join(", "),text:lacking.length+" missing"}):null,
      p.plaintextEnv?h("span",{class:"badge warn",text:".env"}):null),
    h("span",{class:"muted ago",text:ago(p.active)}),
    projectMenu(p));
  dropTarget(row,p);
  draggableProject(row,p);
  return row;
}

/* ------------------------------------------------------- dragging smartly -- */

/** The keys a dragged thing would give: one, a set's, or every set's in a group. */
function keysOfDragged(what){
  const setKeys=function(n){const s=S.library.find(function(x){return x.name===n});return s?s.keys:[]};
  if(what.kind==="key")return [what.key];
  if(what.kind==="set")return setKeys(what.set);
  const g=(S.groups||[]).find(function(x){return x.name===what.group});
  return g?[].concat.apply([],g.sets.map(setKeys)):[];
}
/** While something global is dragged, the projects whose code reads what it holds, and lack it, light up. */
function markWanting(what){
  const ks=keysOfDragged(what);
  [].forEach.call(document.querySelectorAll("[data-root]"),function(el){
    const p=HUB&&HUB.projects.find(function(x){return x.root===el.getAttribute("data-root")});
    const want=p?(p.state==="codebase"?p.credentials||[]:p.lacking||[]).filter(function(k){return ks.indexOf(k)>-1}):[];
    el.classList.toggle("wants",want.length>0);
    if(want.length)el.setAttribute("data-wants","reads "+want.slice(0,2).join(", ")+(want.length>2?"…":""));
  });
}
function clearDragMarks(){
  [].forEach.call(document.querySelectorAll(".drop-on,.wants"),function(x){x.classList.remove("drop-on");x.classList.remove("wants");x.removeAttribute("data-wants")});
}
`;
