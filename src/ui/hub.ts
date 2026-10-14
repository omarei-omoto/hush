/**
 * The hub's own parts of the page: the keys sidebar on the right (every global
 * key, ready to drag onto a project), and what you can do to a project from
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

function renderKeys(){
  const box=document.getElementById("keys");clear(box);
  applyKeysOpen();
  if(!S)return;
  const total=S.library.reduce(function(n,x){return n+x.keys.length},0);
  box.append(h("div",{class:"khead"},
    h("div",null,h("h2",{text:"Global keys"}),
      h("p",{text:total?"Drag one onto a project to make it part of it.":"Keys you keep once and use in any project."})),
    h("button",{type:"button",class:"iconbtn","aria-label":"Close the global keys",title:"Close",onclick:function(){setKeysOpen(false)}},icon("x"))));
  const list=h("div",{class:"klist"});
  if(total>5){
    const q=h("input",{class:"input",type:"search",placeholder:"Find a key",value:KEYS_QUERY,"aria-label":"Find a global key",autocomplete:"off",spellcheck:"false"});
    q.addEventListener("input",function(){KEYS_QUERY=q.value;renderKeyList(list)});
    box.append(q);
  }
  box.append(list,
    h("button",{type:"button",class:"btn sm kadd",onclick:function(){addSecretDialog({target:"library|default"})}},icon("plus"),"Save a global key"));
  renderKeyList(list);
}
function renderKeyList(list){
  clear(list);
  const q=KEYS_QUERY.trim().toLowerCase();
  let shown=0;
  S.library.forEach(function(set){
    const keys=set.keys.filter(function(k){return !q||k.toLowerCase().indexOf(q)>-1||String(set.label).toLowerCase().indexOf(q)>-1});
    if(!keys.length)return;
    const group=h("div",{class:"kgroup"},h("div",{class:"kset",text:set.label}));
    keys.forEach(function(k){
      const row=h("div",{class:"kitem",title:k+" from "+set.label+" — drag onto a project"},
        h("span",{class:"grip"},icon("grip")),h("span",{class:"mono k",text:k}),
        moreButton("More for "+k,function(){return [{label:"Use in a project…",run:function(){giveKeyDialog(set.name,k)}}]}));
      draggableKey(row,set.name,k);
      group.append(row);shown++;
    });
    list.append(group);
  });
  if(!shown)list.append(h("p",{class:"muted kempty",text:q?"No key matches “"+KEYS_QUERY.trim()+"”.":"No global keys yet. Save one, and drag it onto any project."}));
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
