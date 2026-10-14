/**
 * The hub's own parts of the page: the keys sidebar on the right (every global
 * key, set and group, ready to drag onto a project), and what you can do to a project from
 * its ⋯ menu — open it, show it in the file manager, copy its path, look at it
 * again, hide it, or take it off the list.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const HUB_UI = String.raw`
/* ----------------------------------------------------- the keys sidebar -- */

/* Open or closed, remembered per browser; until chosen, open where there is room for it. */
let KEYS_OPEN=(function(){
  try{const v=localStorage.getItem("hush-keys");if(v)return v==="open"}catch(e){}
  return window.innerWidth>1180;
})();
let KEYS_QUERY="";
function setKeysOpen(open){
  KEYS_OPEN=open;
  try{localStorage.setItem("hush-keys",open?"open":"closed")}catch(e){}
  applyKeysOpen();
  if(open){const q=document.querySelector("#keys input");if(q)q.focus()}
}
function applyKeysOpen(){
  document.querySelector(".app").classList.toggle("keys-closed",!KEYS_OPEN);
  const tab=document.getElementById("keystab");
  if(tab)tab.setAttribute("aria-expanded",String(KEYS_OPEN));
}
document.getElementById("keystab").addEventListener("click",function(){setKeysOpen(!KEYS_OPEN)});
document.addEventListener("keydown",function(ev){
  // Escape closes the drawer on a narrow window, where it covers the page.
  if(ev.key==="Escape"&&KEYS_OPEN&&window.innerWidth<=1180&&!document.querySelector("dialog[open]")&&!openMenuEl)setKeysOpen(false);
});

/* Groups folded shut in the sidebar, remembered per browser. */
let KEYS_SHUT=(function(){try{return JSON.parse(localStorage.getItem("hush-groups-shut")||"[]")}catch(e){return []}})();
function toggleShut(slug){
  KEYS_SHUT=KEYS_SHUT.indexOf(slug)>-1?KEYS_SHUT.filter(function(x){return x!==slug}):KEYS_SHUT.concat([slug]);
  try{localStorage.setItem("hush-groups-shut",JSON.stringify(KEYS_SHUT))}catch(e){}
  renderKeyList(document.querySelector("#keys .klist"));
}

function renderKeys(){
  const box=document.getElementById("keys");clear(box);
  applyKeysOpen();
  if(!S)return;
  const sets=globalSets();
  const total=sets.reduce(function(n,x){return n+x.keys.length},0);
  box.append(h("div",{class:"khead"},
    h("div",null,h("h2",{text:"Global keys"}),
      h("p",{text:total?"Drag a key, a set or a whole group onto a project.":"Keys you keep once and use in any project."})),
    h("button",{type:"button",class:"iconbtn","aria-label":"Close the global keys",title:"Close",onclick:function(){setKeysOpen(false)}},icon("x"))));
  const list=h("div",{class:"klist"});
  if(total>5){
    const q=h("input",{class:"input",type:"search",placeholder:"Find a key",value:KEYS_QUERY,"aria-label":"Find a global key",autocomplete:"off",spellcheck:"false"});
    q.addEventListener("input",function(){KEYS_QUERY=q.value;renderKeyList(list)});
    box.append(q);
  }
  box.append(list,
    h("div",{class:"kfoot"},
      h("button",{type:"button",class:"btn sm kadd",onclick:function(){addSecretDialog({target:"library|default"})}},icon("plus"),"Save a global key"),
      sets.length>1?h("button",{type:"button",class:"btn sm ghost",onclick:function(){newGroupDialog()}},icon("folder"),"New group"):null));
  renderKeyList(list);
}

/* What a set's ⋯ offers, in the sidebar and on Global keys. */
function globalSetMenu(set){
  const here=S.folder.state!=="unset"&&route()!=="home"&&S.used.indexOf(linkOf(set))>-1;
  return [
    {label:"Use in a project…",run:function(){giveKeyDialog({kind:"set",set:set.name})}},
    set.name==="default"?null:{label:set.group?"Move to another group…":"Put in a group…",run:function(){groupPickDialog(set)}},
    set.name==="default"?null:{label:here?"Keep for "+folderName()+" only":"Keep for one project only…",run:function(){
      if(here)place({action:"here",set:set.name});
      else pickProjectDialog("Keep "+set.label+" for one project","Only that project gets it from now on, and hush refuses it anywhere else. It leaves your global keys.",
        function(p){place({action:"here",set:set.name,project:p.root})});
    }},
    {label:"Edit name and description…",run:function(){editSetDialog("library",set)}},
  ];
}
function globalKeyMenu(set,k){
  return [
    {label:"Use in a project…",run:function(){giveKeyDialog({kind:"key",set:set.name,key:k})}},
    {label:"Keep for one project only…",run:function(){
      pickProjectDialog("Keep "+k+" for one project","It moves out of "+set.label+" into that project's own keys. Only that project gets it from now on.",
        function(p){place({action:"here",set:set.name,key:k,project:p.root})});
    }},
  ];
}
function groupMenu(g){
  return [
    {label:"Use in a project…",run:function(){giveKeyDialog({kind:"group",group:g.name})}},
    {label:"Rename…",run:function(){renameGroupDialog(g)}},
    "-",
    {label:"Ungroup",run:function(){
      confirmDialog("Ungroup "+g.label+"?","Its "+plural(g.sets.length,"set")+" stay in your global keys, just not in a group. A project that uses the group keeps each set.","Ungroup",
        async function(){const r=await api("/api/group",{action:"ungroup",group:g.name});await refresh(r);toast(r.done)});
    }},
  ];
}

function renderKeyList(list){
  if(!list)return;
  clear(list);
  const q=KEYS_QUERY.trim().toLowerCase();
  const sets=globalSets();
  let shown=0;
  /* One set: its name (drag it for the whole set) and its keys (drag one for just that key). */
  function setBlock(set,groupLabel){
    const hit=function(k){return !q||k.toLowerCase().indexOf(q)>-1||String(set.label).toLowerCase().indexOf(q)>-1||String(groupLabel||"").toLowerCase().indexOf(q)>-1};
    const keys=set.keys.filter(hit);
    if(q&&!keys.length)return null;
    const head=h("div",{class:"kset",title:set.label+" — drag for the whole set"},
      h("span",{class:"grip"},icon("grip")),h("span",{class:"kname",text:set.label}),h("span",{class:"count",text:String(set.keys.length)}),
      moreButton("More for "+set.label,function(){return globalSetMenu(set)}));
    draggable(head,{kind:"set",set:set.name});
    const block=h("div",{class:"kgroup"},head);
    keys.forEach(function(k){
      const row=h("div",{class:"kitem",title:k+" from "+set.label+" — drag onto a project"},
        h("span",{class:"grip"},icon("grip")),h("span",{class:"mono k",text:k}),
        moreButton("More for "+k,function(){return globalKeyMenu(set,k)}));
      draggableKey(row,set.name,k);
      block.append(row);shown++;
    });
    if(!set.keys.length)block.append(h("div",{class:"muted kempty",text:"no keys yet"}));
    return block;
  }
  (S.groups||[]).forEach(function(g){
    const members=g.sets.map(function(n){return sets.find(function(x){return x.name===n})}).filter(Boolean);
    const blocks=members.map(function(set){return setBlock(set,g.label)}).filter(Boolean);
    if(q&&!blocks.length&&g.label.toLowerCase().indexOf(q)<0)return;
    const shut=!q&&KEYS_SHUT.indexOf(g.name)>-1;
    const head=h("div",{class:"kfolder",title:g.label+" — drag for the whole group"},
      h("button",{type:"button",class:"iconbtn fold","aria-expanded":String(!shut),"aria-label":(shut?"Open ":"Fold ")+g.label,onclick:function(){toggleShut(g.name)}},icon(shut?"right":"down")),
      icon("folder"),h("span",{class:"kname",text:g.label}),h("span",{class:"count",text:plural(members.length,"set")}),
      moreButton("More for "+g.label,function(){return groupMenu(g)}));
    draggable(head,{kind:"group",group:g.name});
    const box=h("div",{class:"kfold"},head);
    if(!shut)blocks.forEach(function(b){box.append(b)});
    list.append(box);
  });
  sets.filter(function(s){return !s.group}).forEach(function(set){const b=setBlock(set,"");if(b)list.append(b)});
  if(!shown&&!(S.groups||[]).length)list.append(h("p",{class:"muted kempty",text:q?"No key matches “"+KEYS_QUERY.trim()+"”.":"No global keys yet. Save one, and drag it onto any project."}));
  else if(!shown&&q)list.append(h("p",{class:"muted kempty",text:"No key matches “"+KEYS_QUERY.trim()+"”."}));
}

/* -------------------------------------------------------------- groups -- */

/** Put one global set into a group: one there is, a new one, or none. */
function groupPickDialog(set){
  const grp=groupChooser(set.group||"");
  dialog({title:"Put "+set.label+" in a group",lead:"A group is a folder for your global keys. Drag one onto a project and it gets every set in it — including ones you add later.",
    submit:"Save",body:[grp.el],
    onSubmit:async function(){
      const g=grp.value();
      if(g===null){toast("name the group",{error:true});return false}
      const r=await api("/api/group",{action:"file",set:set.name,group:g||null});
      await refresh(r);toast(r.done);
    }});
}
function newGroupDialog(){
  const name=h("input",{class:"input",placeholder:"e.g. AI stack"});
  const boxes=h("div",{class:"card list"});
  const checks=[];
  globalSets().filter(function(s){return s.name!=="default"}).forEach(function(set){
    const cb=h("input",{type:"checkbox"});
    checks.push({cb:cb,set:set});
    boxes.append(h("label",{class:"offer",style:"cursor:pointer"},cb,
      h("div",{class:"what"},h("b",{text:set.label}),h("div",{text:(set.group?"now in "+set.group+" · ":"")+(set.keys.join(", ")||"no keys yet")}))));
  });
  dialog({title:"New group",lead:"A folder for global sets that go together, like everything one stack needs. Drag the group onto a project and it gets all of them.",
    submit:"Create group",body:[field("Name",name),h("div",{class:"field"},h("span",{text:"Sets in it"}),boxes)],
    onSubmit:async function(){
      const label=name.value.trim();
      const picked=checks.filter(function(c){return c.cb.checked});
      if(!label){toast("name the group",{error:true});name.focus();return false}
      if(!picked.length){toast("tick at least one set to put in it",{error:true});return false}
      let r=null;
      for(const c of picked)r=await api("/api/group",{action:"file",set:c.set.name,group:label});
      await refresh(r);toast(label+" holds "+plural(picked.length,"set"));
    }});
}
function renameGroupDialog(g){
  const name=h("input",{class:"input",value:g.label});
  dialog({title:"Rename "+g.label,lead:"Projects that use the group keep using it.",submit:"Rename",body:[field("Name",name)],
    onSubmit:async function(){
      if(!name.value.trim()){name.focus();return false}
      const r=await api("/api/group",{action:"rename",group:g.name,label:name.value.trim()});
      await refresh(r);toast(r.done);
    }});
}

/* An open project's page takes a dropped key too. */
dropTarget(document.getElementById("page"),function(){
  return S&&route()==="project"&&S.folder.state!=="unset"?{root:currentRoot(),name:folderName()}:null;
});

/* ------------------------------------------------ a project's ⋯ menu -- */

function revealLabel(){
  const p=HUB&&HUB.platform;
  return p==="darwin"?"Show in Finder":p==="win32"?"Show in Explorer":"Open the folder";
}
function projectMenuItems(p){
  return [
    {label:"Open",run:function(){openProject(p.root)}},
    {label:revealLabel(),run:function(){revealProject(p)}},
    {label:"Copy path",run:function(){copyText(p.root,"the path")}},
    {label:"Rescan",run:function(){projectAction(p,"rescan","looked at "+p.name+" again")}},
    {label:p.group?"Move to another group…":"Put in a group…",run:function(){projectGroupDialog(p)}},
    "-",
    {label:"Hide",run:function(){
      projectAction(p,"hide",p.name+" is hidden — Home lists it under Hidden",{label:"Undo",run:function(){projectAction(p,"show",p.name+" is back")}});
    }},
    {label:"Remove from list…",danger:true,run:function(){removeProjectDialog(p)}},
  ];
}
function projectMenu(p){return moreButton("More for "+p.name,function(){return projectMenuItems(p)})}

/** hide, show, remove or rescan one project, then show the list as it now is. */
async function projectAction(p,action,msg,undo){
  const r=await api("/api/projects",{action:action,root:p.root});
  HUB=r;
  if(msg)toast(msg,undo?{action:undo}:null);
  // The project on screen just left the list: go back to all of them.
  if((action==="hide"||action==="remove")&&CUR===p.root){
    setProject(null);location.hash="#home";
    await refresh();
    return;
  }
  render();
}
async function revealProject(p){
  const r=await api("/api/projects",{action:"reveal",root:p.root});
  if(!r.revealed)toast("No file manager to open here — the folder is "+p.root,{error:true});
}
function removeProjectDialog(p){
  confirmDialog("Remove "+p.name+" from the list?",
    "hush forgets it: it leaves this list, and looking through your folders won't add it back. Nothing is deleted — its files, and its .hush folder if it has one, stay exactly as they are. To bring it back, add the folder again.",
    "Remove from list",
    async function(){await projectAction(p,"remove",p.name+" is off the list")});
}

/* ------------------------------------------------ Home: hidden projects -- */

function hiddenSection(){
  const hidden=(HUB&&HUB.hidden)||[];
  if(!hidden.length)return null;
  const list=h("div",{class:"card list"});
  hidden.forEach(function(p){
    list.append(h("div",{class:"li"},icon("eyeoff"),
      h("div",{class:"body"},h("div",{class:"t",text:p.name}),h("div",{class:"d mono",text:tildePath(p.root)})),
      h("button",{type:"button",class:"btn sm",onclick:function(){projectAction(p,"show",p.name+" is back")}},icon("eye"),"Show"),
      h("button",{type:"button",class:"btn sm ghost",onclick:function(){removeProjectDialog(p)}},"Remove…")));
  });
  return h("details",{class:"section hiddenlist"},
    h("summary",null,h("span",{text:"Hidden"}),h("span",{class:"count",text:String(hidden.length)})),
    h("p",{class:"muted",text:"Off your list, and they stay off — using hush in one, or looking through your folders, won't bring it back. Show puts one back."}),
    list);
}
`;
