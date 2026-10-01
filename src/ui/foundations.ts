/**
 * The body's frame, then the script's foundations: the session token, h() (the only way anything is put on the page), the model, and menus.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const FOUNDATIONS = String.raw`<div class="app">
  <aside class="side">
    <div class="brand"><svg class="lockup" viewBox="1.011 3.967 51.022 12.505" role="img" aria-label="hush"><g fill="currentColor"><g transform="translate(1.811 5.342) scale(0.096)"><path d="M19.15 0H28.57V14.29H14.29V4.87A4.87 4.87 0 0 1 19.15 0ZM28.57 0H37.99A4.87 4.87 0 0 1 42.86 4.87V14.29H28.57V0ZM133.44 0H142.86V14.29H128.57V4.87A4.87 4.87 0 0 1 133.44 0ZM142.86 0H152.28A4.87 4.87 0 0 1 157.14 4.87V14.29H142.86V0ZM14.29 14.29H28.57V28.57H14.29V14.29ZM28.57 14.29H42.86V28.57H28.57V14.29ZM128.57 14.29H142.86V28.57H128.57V14.29ZM142.86 14.29H157.14V28.57H142.86V14.29ZM14.29 28.57H28.57V42.86H14.29V28.57ZM28.57 28.57H42.86V42.86H28.57V28.57ZM128.57 28.57H142.86V42.86H128.57V28.57ZM142.86 28.57H157.14V37.99A4.87 4.87 0 0 1 152.28 42.86H142.86V28.57ZM4.87 42.86H14.29V57.14H0V47.72A4.87 4.87 0 0 1 4.87 42.86ZM14.29 42.86H28.57V57.14H14.29V42.86ZM28.57 42.86H42.86V57.14H28.57V42.86ZM42.86 42.86H57.14V57.14H42.86V42.86ZM57.14 42.86H71.43V57.14H57.14V42.86ZM71.43 42.86H85.71V57.14H71.43V42.86ZM85.71 42.86H100V57.14H85.71V42.86ZM100 42.86H114.29V57.14H100V42.86ZM114.29 42.86H128.57V57.14H114.29V42.86ZM128.57 42.86H142.86V57.14H128.57V42.86ZM0 57.14H14.29V71.43H0V57.14ZM14.29 57.14H28.57V71.43H14.29V57.14ZM114.29 57.14H128.57V71.43H114.29V57.14ZM128.57 57.14H142.86V71.43H128.57V57.14ZM0 71.43H14.29V85.71H0V71.43ZM14.29 71.43H28.57V85.71H14.29V71.43ZM114.29 71.43H128.57V85.71H114.29V71.43ZM128.57 71.43H142.86V85.71H128.57V71.43ZM0 85.71H14.29V100H4.87A4.87 4.87 0 0 1 0 95.13V85.71ZM14.29 85.71H28.57V95.13A4.87 4.87 0 0 1 23.7 100H14.29V85.71ZM114.29 85.71H128.57V100H119.15A4.87 4.87 0 0 1 114.29 95.13V85.71ZM128.57 85.71H142.86V95.13A4.87 4.87 0 0 1 137.99 100H128.57V85.71ZM14.29 42.86L9.42 42.86A4.87 4.87 0 0 0 14.29 37.99ZM42.86 42.86L47.72 42.86A4.87 4.87 0 0 1 42.86 37.99ZM128.57 42.86L123.7 42.86A4.87 4.87 0 0 0 128.57 37.99ZM142.86 42.86L147.72 42.86A4.87 4.87 0 0 0 142.86 47.72ZM28.57 57.14L33.44 57.14A4.87 4.87 0 0 0 28.57 62.01ZM114.29 57.14L109.42 57.14A4.87 4.87 0 0 1 114.29 62.01Z"/></g><g transform="translate(19.87 15.459) scale(0.007)"><path d="M920.0013427734375 0.0V-551.3345947265625Q920.0013427734375 -641.0028686523438 903.0009460449219 -716.50341796875Q886.0005493164062 -792.0039672851562 848.3333740234375 -848.3372497558594Q810.6661987304688 -904.6705322265625 751.1658325195312 -935.6702880859375Q691.6654663085938 -966.6700439453125 606.66552734375 -966.6700439453125Q528.99755859375 -966.6700439453125 469.3302917480469 -940.0028991699219Q409.66302490234375 -913.3357543945312 369.32952880859375 -862.8351745605469Q328.99603271484375 -812.3345947265625 308.1627502441406 -740.0009155273438Q287.3294677734375 -667.667236328125 287.3294677734375 -576.0008544921875L183.3310546875 -599.3326416015625Q183.3310546875 -765.3338012695312 241.33123779296875 -878.3338317871094Q299.3314208984375 -991.3338623046875 401.1646728515625 -1049.0001831054688Q502.9979248046875 -1106.66650390625 635.3304443359375 -1106.66650390625Q732.3295288085938 -1106.66650390625 804.6626281738281 -1077.000244140625Q876.9957275390625 -1047.333984375 927.4959106445312 -996.3344421386719Q977.99609375 -945.3348999023438 1008.9964599609375 -879.5017395019531Q1039.996826171875 -813.6685791015625 1053.9971313476562 -740.3348083496094Q1067.9974365234375 -667.0010375976562 1067.9974365234375 -593.9996337890625V0.0ZM139.3333740234375 0.0V-1440.0H271.9967041015625V-626.6644287109375H287.3294677734375V0.0ZM1650.6669921875 26.66650390625Q1553.6679077148438 26.66650390625 1481.3348083496094 -2.999755859375Q1409.001708984375 -32.666015625 1358.5015258789062 -83.66555786132812Q1308.0013427734375 -134.66510009765625 1277.0009765625 -200.49826049804688Q1246.0006103515625 -266.3314208984375 1232.0003051757812 -339.6651916503906Q1218.0 -412.99896240234375 1218.0 -486.0003662109375V-1080H1365.99609375V-528.6654052734375Q1365.99609375 -439.663818359375 1382.9964904785156 -363.8299255371094Q1399.9968872070312 -287.99603271484375 1437.6640625 -231.66275024414062Q1475.3312377929688 -175.3294677734375 1534.8316040039062 -144.3297119140625Q1594.3319702148438 -113.3299560546875 1679.3319091796875 -113.3299560546875Q1756.9998779296875 -113.3299560546875 1816.6671447753906 -139.99710083007812Q1876.3344116210938 -166.66424560546875 1916.6679077148438 -217.16482543945312Q1957.0014038085938 -267.6654052734375 1977.8346862792969 -340.1657409667969Q1998.66796875 -412.66607666015625 1998.66796875 -503.9991455078125L2102.6663818359375 -480.6673583984375Q2102.6663818359375 -314.66619873046875 2044.6661987304688 -201.66616821289062Q1986.666015625 -88.6661376953125 1884.832763671875 -30.99981689453125Q1782.99951171875 26.66650390625 1650.6669921875 26.66650390625ZM2014.000732421875 0.0V-265.9971923828125H1998.66796875V-1080.0H2145.9974365234375V0.0ZM2739.332763671875 28.6666259765625Q2549.3331909179688 28.6666259765625 2426.833282470703 -53.1663818359375Q2304.3333740234375 -134.9993896484375 2276.0 -281.33203125L2425.99609375 -305.9981689453125Q2449.6629638671875 -213.9976806640625 2535.4971313476562 -159.66400146484375Q2621.331298828125 -105.330322265625 2747.3323974609375 -105.330322265625Q2870.0005493164062 -105.330322265625 2941.001495361328 -156.83102416992188Q3012.00244140625 -208.33172607421875 3012.00244140625 -297.3328857421875Q3012.00244140625 -347.33343505859375 2989.3355712890625 -378.83380126953125Q2966.668701171875 -410.33416748046875 2897.8349609375 -437.33441162109375Q2829.001220703125 -464.33465576171875 2692.0006103515625 -501.3348388671875Q2545.33349609375 -540.6683349609375 2462.000030517578 -581.0016174316406Q2378.6665649414062 -621.3348999023438 2343.9999084472656 -673.834716796875Q2309.333251953125 -726.3345336914062 2309.333251953125 -802.0009765625Q2309.333251953125 -894.0006103515625 2360.9998779296875 -963.5003967285156Q2412.66650390625 -1033.0001831054688 2504.833038330078 -1071.5000915527344Q2596.9995727539062 -1110.0 2719.3326416015625 -1110.0Q2840.9991455078125 -1110.0 2937.3324279785156 -1070.6666564941406Q3033.6657104492188 -1031.3333129882812 3092.8323364257812 -960.3333435058594Q3151.9989624023438 -889.3333740234375 3162.66552734375 -795.33349609375L3012.66943359375 -768.0008544921875Q2997.669189453125 -863.3352661132812 2918.3348083496094 -918.6692199707031Q2839.0004272460938 -974.003173828125 2717.3323974609375 -976.0030517578125Q2602.3311767578125 -979.0029907226562 2530.1636962890625 -932.6690063476562Q2457.9962158203125 -886.3350219726562 2457.9962158203125 -809.3341064453125Q2457.9962158203125 -766.0003051757812 2483.8297424316406 -735.3332824707031Q2509.6632690429688 -704.666259765625 2578.1634826660156 -677.9993896484375Q2646.6636962890625 -651.33251953125 2773.9970703125 -619.33251953125Q2922.9978637695312 -581.3323364257812 3008.1648559570312 -539.1656799316406Q3093.3318481445312 -496.9990234375 3128.998565673828 -439.8324279785156Q3164.665283203125 -382.66583251953125 3164.665283203125 -299.33251953125Q3164.665283203125 -145.99957275390625 3051.3321533203125 -58.666473388671875Q2937.9990234375 28.6666259765625 2739.332763671875 28.6666259765625ZM4076.0013427734375 0.0V-551.3345947265625Q4076.0013427734375 -641.0028686523438 4059.000946044922 -716.50341796875Q4042.0005493164062 -792.0039672851562 4004.3333740234375 -848.3372497558594Q3966.6661987304688 -904.6705322265625 3907.1658325195312 -935.6702880859375Q3847.6654663085938 -966.6700439453125 3762.66552734375 -966.6700439453125Q3684.99755859375 -966.6700439453125 3625.330291748047 -940.0028991699219Q3565.6630249023438 -913.3357543945312 3525.3295288085938 -862.8351745605469Q3484.9960327148438 -812.3345947265625 3464.1627502441406 -740.0009155273438Q3443.3294677734375 -667.667236328125 3443.3294677734375 -576.0008544921875L3339.3310546875 -599.3326416015625Q3339.3310546875 -765.3338012695312 3397.3312377929688 -878.3338317871094Q3455.3314208984375 -991.3338623046875 3557.1646728515625 -1049.0001831054688Q3658.9979248046875 -1106.66650390625 3791.3304443359375 -1106.66650390625Q3888.3295288085938 -1106.66650390625 3960.662628173828 -1077.000244140625Q4032.9957275390625 -1047.333984375 4083.4959106445312 -996.3344421386719Q4133.99609375 -945.3348999023438 4164.9964599609375 -879.5017395019531Q4195.996826171875 -813.6685791015625 4209.997131347656 -740.3348083496094Q4223.9974365234375 -667.0010375976562 4223.9974365234375 -593.9996337890625V0.0ZM3295.3333740234375 0.0V-1440.0H3427.9967041015625V-626.6644287109375H3443.3294677734375V0.0Z"/></g></g></svg></div>
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
