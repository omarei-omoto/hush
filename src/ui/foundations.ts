/**
 * The body's frame, then the script's foundations: the session token, h() (the only way anything is put on the page), the model, and menus.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const FOUNDATIONS = String.raw`<div class="app">
  <aside class="side">
    <div class="brand"><svg viewBox="0 0 64 64" aria-hidden="true"><rect x="10" y="6" width="44" height="52" rx="7" fill="none" stroke="currentColor" stroke-width="4"/><rect x="20" y="18" width="24" height="3" rx="1.5" fill="currentColor" opacity=".45"/><rect x="18" y="28" width="28" height="9" rx="2" fill="currentColor"/><rect x="20" y="45" width="16" height="3" rx="1.5" fill="currentColor" opacity=".45"/></svg><span>hush</span></div>
    <div class="here" id="here"></div>
    <nav class="nav" id="nav" aria-label="Sections"></nav>
    <a class="level" id="level" href="#agent"></a>
  </aside>
  <main class="main"><div class="page" id="page"></div></main>
</div>
<div class="drop" id="drop" aria-hidden="true">Drop to import<small>.env files — nothing is saved until you review them</small></div>
<input type="file" id="picker" multiple hidden>
<div class="toasts" id="toasts" role="status" aria-live="polite"></div>
<script>
"use strict";
/*
 * The session token arrives in the link's fragment (#t=…), which a browser
 * never sends to a server and nothing logs as a URL. It is read once, the
 * address bar is cleaned so history, sync and a screenshot hold no token, and
 * it is kept for this tab only so a reload still works.
 */
const T=(function(){
  let t="";
  const m=/(?:^|[#&?])t=([A-Za-z0-9_-]{16,})/.exec(location.hash+"&"+location.search.slice(1));
  if(m){
    t=m[1];
    try{sessionStorage.setItem("hush-t",t)}catch(e){}
    // Keep a section named alongside the token (#t=…&team), drop the token.
    const rest=location.hash.slice(1).split("&").filter(function(p){return p&&!/^t=/.test(p)}).join("&");
    history.replaceState(null,"",location.pathname+(rest?"#"+rest:""));
  }else{
    try{t=sessionStorage.getItem("hush-t")||""}catch(e){}
  }
  return t;
})();
let S=null;

/* ------------------------------------------------------------ foundations */

/** Build an element. Children are nodes or text; text is only ever text. */
function h(tag,props){
  const el=document.createElement(tag);
  if(props)for(const k of Object.keys(props)){
    const v=props[k];
    if(v===null||v===undefined||v===false)continue;
    if(k==="class")el.className=v;
    else if(k==="text")el.textContent=v;
    else if(k.slice(0,2)==="on")el.addEventListener(k.slice(2),v);
    else if(k==="value")el.value=v;
    else if(k==="checked"||k==="disabled"||k==="hidden"||k==="required"||k==="multiple")el[k]=Boolean(v);
    else el.setAttribute(k,v===true?"":String(v));
  }
  for(let i=2;i<arguments.length;i++)add(el,arguments[i]);
  return el;
}
function add(el,c){
  if(c===null||c===undefined||c===false)return;
  if(Array.isArray(c)){c.forEach(function(x){add(el,x)});return}
  el.append(c instanceof Node?c:String(c));
}
function clear(el){while(el.firstChild)el.removeChild(el.firstChild)}

const ICONS={
  folder:"M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z",
  library:"M4 5h4v14H4zM10 5h4v14h-4zM16 6l3.5-1 3 13.5-3.5 1z",
  team:"M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21v-1a6 6 0 0 1 12 0v1M16 3.5a4 4 0 0 1 0 7.5M22 21v-1a6 6 0 0 0-4-5.6",
  agent:"M12 3v3M8 21h8M5 8h14a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2zM9 13h.01M15 13h.01",
  activity:"M3 12h4l3-8 4 16 3-8h4",
  plus:"M12 5v14M5 12h14",
  upload:"M12 16V4M7 9l5-5 5 5M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2",
  more:"M5 12h.01M12 12h.01M19 12h.01",
  up:"M6 15l6-6 6 6",
  down:"M6 9l6 6 6-6",
  eye:"M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  eyeoff:"M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2",
  copy:"M9 9h10v10H9zM5 15V5h10",
  check:"M5 12.5l4.5 4.5L19 7",
  alert:"M12 9v4M12 17h.01M10.3 3.9L2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  info:"M12 16v-4M12 8h.01M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z",
  lock:"M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4",
  x:"M6 6l12 12M18 6L6 18",
};
function icon(name){
  const s=document.createElementNS("http://www.w3.org/2000/svg","svg");
  s.setAttribute("viewBox","0 0 24 24");s.setAttribute("class","i");s.setAttribute("aria-hidden","true");
  const p=document.createElementNS("http://www.w3.org/2000/svg","path");
  p.setAttribute("d",ICONS[name]||"");
  if(name==="more")p.setAttribute("stroke-width","3.2");
  s.append(p);return s;
}

function toast(msg,opts){
  const box=document.getElementById("toasts");
  const t=h("div",{class:"toast"+(opts&&opts.error?" err":"")},h("span",{text:msg}));
  if(opts&&opts.action){
    t.append(h("button",{type:"button",onclick:function(){t.remove();opts.action.run()}},opts.action.label));
  }
  box.append(t);
  setTimeout(function(){t.remove()},opts&&opts.action?7000:3200);
}

async function api(path,body){
  const r=await fetch(path,{method:body?"POST":"GET",headers:{"x-hush-token":T,"content-type":"application/json"},
    body:body?JSON.stringify(body):undefined});
  let j={};
  try{j=await r.json()}catch(e){j={error:"the hush server did not answer — is it still running?"}}
  if(!r.ok){toast(j.error||"that did not work",{error:true});throw new Error(j.error||"failed")}
  return j;
}
async function refresh(next){
  S=next&&next.folder?next:await api("/api/state");
  // The library's default set is its catch-all; "default" beside this
  // project's own default would read as the same thing.
  S.library.forEach(function(x){if(x.name==="default"&&x.label==="default")x.label="Catch-all"});
  render();
}

function plural(n,one,many){return n+" "+(n===1?one:(many||one+"s"))}
function initials(name){return String(name||"?").split(/[\s._-]+/).filter(Boolean).slice(0,2).map(function(w){return w.charAt(0).toUpperCase()}).join("")||"?"}
function folderName(){return S.folder.root.replace(/[\\/]+$/,"").split(/[\\/]/).pop()||S.folder.root}
const VAULT_MADE="made this project's vault — commit .hush/vault.json so the team gets it";

/* ------------------------------------------------------------ the model -- */

/** Every set a run gets, in the order they apply, with the card data for each. */
function usedSets(){
  return S.used.map(function(name,i){
    if(name==="library:default"){
      const lib=S.library.find(function(x){return x.name==="default"});
      return lib?{set:lib,where:"library",link:name,index:i}:null;
    }
    const proj=S.project.find(function(x){return x.name===name});
    if(proj)return {set:proj,where:"project",link:name,index:i};
    if(name==="default")return {set:{name:"default",label:"default",keys:[],secrets:[],description:"",whenToUse:""},where:"project",link:name,index:i,placeholder:true};
    const lib=S.library.find(function(x){return x.name===name});
    return lib?{set:lib,where:"library",link:name,index:i}:{missing:name,link:name,index:i};
  }).filter(Boolean);
}

/** KEY -> the label of the set whose value a run actually gets (the last one to define it). */
function winners(){
  const w={};
  usedSets().forEach(function(u){if(u.set)u.set.keys.forEach(function(k){w[k]={label:u.set.label,link:u.link}})});
  return w;
}

/** An unused set that already holds this key — this project's own first, then the library. */
function sourceFor(key){
  const p=S.project.find(function(x){return S.used.indexOf(x.name)<0&&x.keys.indexOf(key)>-1});
  if(p)return {set:p,link:p.name};
  const l=S.library.find(function(x){const link=x.name==="default"?"library:default":x.name;return S.used.indexOf(link)<0&&x.keys.indexOf(key)>-1});
  return l?{set:l,link:l.name==="default"?"library:default":l.name}:null;
}

function setLabel(where,name){
  const list=where==="library"?S.library:S.project;
  const s=list.find(function(x){return x.name===name});
  return s?s.label:name;
}

/* ------------------------------------------------------------ menus -- */

let openMenuEl=null;
function closeMenu(){if(openMenuEl){openMenuEl.remove();openMenuEl=null}}
function menu(anchor,items){
  closeMenu();
  const m=h("div",{class:"menu",role:"menu"});
  items.forEach(function(it){
    if(it==="-"){m.append(h("hr"));return}
    if(!it)return;
    m.append(h("button",{type:"button",role:"menuitem",class:it.danger?"dangerous":"",onclick:function(){closeMenu();anchor.focus();it.run()}},it.label));
  });
  document.body.append(m);
  const r=anchor.getBoundingClientRect();
  const w=m.offsetWidth,hh=m.offsetHeight;
  m.style.left=Math.max(8,Math.min(r.right-w,window.innerWidth-w-8))+"px";
  m.style.top=(r.bottom+hh+8>window.innerHeight?Math.max(8,r.top-hh-4):r.bottom+4)+"px";
  openMenuEl=m;
  const buttons=[].slice.call(m.querySelectorAll("button"));
  if(buttons[0])buttons[0].focus();
  m.addEventListener("keydown",function(ev){
    const i=buttons.indexOf(document.activeElement);
    if(ev.key==="ArrowDown"){ev.preventDefault();buttons[(i+1)%buttons.length].focus()}
    else if(ev.key==="ArrowUp"){ev.preventDefault();buttons[(i-1+buttons.length)%buttons.length].focus()}
    else if(ev.key==="Escape"||ev.key==="Tab"){ev.preventDefault();closeMenu();anchor.focus()}
  });
}
document.addEventListener("mousedown",function(ev){if(openMenuEl&&!openMenuEl.contains(ev.target))closeMenu()});
window.addEventListener("resize",closeMenu);
window.addEventListener("scroll",closeMenu,true);
function moreButton(label,items){
  const b=h("button",{type:"button",class:"iconbtn","aria-label":label,"aria-haspopup":"menu"},icon("more"));
  b.onclick=function(){menu(b,typeof items==="function"?items():items)};
  return b;
}

/**
 * A modal dialog. submit() may return false to keep it open (a validation
 * message was shown); throwing keeps it open too, with the error toasted by api().
 */
function dialog(opts){
  const d=h("dialog",{class:opts.wide?"wide":""});
  const f=h("form",{class:"dlg",method:"dialog",novalidate:true});
  const head=h("div",{class:"dh"},h("h2",{text:opts.title}),opts.lead?h("p",{text:opts.lead}):null);
  const body=h("div",{class:"db"});
  add(body,opts.body);
  const ok=h("button",{type:"submit",class:"btn "+(opts.danger?"danger":"primary")},opts.submit||"Save");
  const cancel=h("button",{type:"button",class:"btn ghost",onclick:function(){close()}},opts.cancel||"Cancel");
  const foot=h("div",{class:"df"},opts.left||null,cancel,opts.noSubmit?null:ok);
  f.append(head,body,foot);d.append(f);
  let busy=false;
  f.addEventListener("submit",async function(ev){
    ev.preventDefault();
    if(busy||!opts.onSubmit){if(!opts.onSubmit)close();return}
    busy=true;ok.disabled=true;
    try{if(await opts.onSubmit()!==false)close()}catch(e){/* api() already said why */}
    finally{busy=false;ok.disabled=false}
  });
  function close(){d.close()}
  d.addEventListener("close",function(){d.remove();if(opts.onClose)opts.onClose()});
  document.body.append(d);
  d.showModal();
  const first=body.querySelector("input:not([type=checkbox]):not([type=radio]),select,textarea");
  if(first)first.focus();
  return {el:d,close:close,ok:ok,body:body};
}
function field(label,control,hint){
  return h("label",{class:"field"},h("span",{text:label}),control,hint?h("small",{text:hint}):null);
}
function confirmDialog(title,lead,label,run){
  dialog({title:title,lead:lead,submit:label,danger:true,onSubmit:run});
}

`;
