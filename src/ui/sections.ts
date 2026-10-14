/**
 * The Project, Library and Team sections.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const SECTIONS = String.raw`/* ---------------------------------------------------------------- project */

/* The setup checklist's remaining steps (src/setup.ts, the same list hush
   setup and hush start use). Each runs in a terminal, so the card offers the
   command to copy, a Skip, and the prompt that hands the rest to an agent. */
const AGENT_PROMPT="Set up hush in this project. Run hush setup --json and follow it: run each step's command as written, ask me in the chat for anything marked \"choice\", and for anything marked \"person\", run it and wait for me. Never open a .env file or ask me for a key in the chat.";
async function copyText(text,what){
  try{await navigator.clipboard.writeText(text);toast("copied "+what)}catch(e){toast("copying is blocked here — select the text instead",{error:true})}
}
async function skipStep(id){await refresh(await api("/api/setup-skip",{id:id,skip:true}))}
function onboardingCard(){
  const o=S.onboarding;
  if(!o||!o.next)return null;
  const todo=o.steps.filter(function(s){return s.status==="todo"});
  const card=h("section",{class:"card pad","aria-label":"Finish setting up"});
  card.append(h("div",{class:"sechead",style:"margin:0"},
    h("div",null,h("h3",{text:"Finish setting up"}),
      h("p",{class:"lead",text:o.done+" of "+o.total+" done. Each step runs in your terminal, or hand them to your coding agent."})),
    h("button",{type:"button",class:"btn sm",onclick:function(){copyText(AGENT_PROMPT,"the prompt for your agent")}},icon("copy"),"Prompt for your agent")));
  const list=h("div",{class:"stack",style:"margin-top:14px"});
  todo.forEach(function(s){
    list.append(h("div",{class:"offer"},
      h("div",{class:"what"},h("b",{text:s.title}),h("div",{text:s.detail}),
        s.command?h("code",{text:s.command,style:"font-size:12.5px;display:block;margin-top:4px"}):null,
        s.kind==="person"?h("div",{class:"muted",text:"Asks you before it changes anything."}):null),
      s.command?h("button",{type:"button",class:"btn sm",onclick:function(){copyText(s.command,"the command")}},icon("copy"),"Copy"):null,
      h("button",{type:"button",class:"btn sm ghost",onclick:function(){skipStep(s.id)}},"Skip")));
  });
  card.append(list);
  return card;
}

function needsCard(){
  const needs=S.needs||[];
  if(!needs.length)return null;
  const win=winners();
  const missing=needs.filter(function(n){return !win[n.name]});
  const card=h("section",{class:"card pad","aria-label":"What your code reads"});
  const head=h("div",{class:"sechead",style:"margin:0"},
    h("div",null,h("h3",{text:"What your code reads"}),
      h("p",{class:"lead",text:plural(needs.length,"variable")+" found in the code — "+(missing.length
        ?missing.length+" not provided yet. A run would start without "+(missing.length===1?"it":"them")+"."
        :"every one is provided.")+(S.needsOrdinary?" Ordinary settings like NODE_ENV and PORT ("+S.needsOrdinary+") are left out.":"")+(S.needsPartial?" This folder is too big to read in full, so the list is partial: open hush ui inside the project for all of it.":"")})),
    h("div",{class:"tally"},
      h("span",{class:"badge ok"},icon("check"),(needs.length-missing.length)+" provided"),
      missing.length?h("span",{class:"badge warn"},icon("alert"),missing.length+" missing"):null));
  card.append(head);
  const list=h("div",{class:"needs"});
  const sorted=missing.concat(needs.filter(function(n){return win[n.name]}));
  const LIMIT=40;
  sorted.forEach(function(n,i){
    const site=n.sites&&n.sites.length?n.sites[0]:"";
    if(win[n.name]){
      list.append(h("span",{class:"need ok",title:"from "+win[n.name].label+(site?" · read in "+site:""),hidden:i>=LIMIT},icon("check"),n.name,h("span",{class:"from",text:win[n.name].label})));
    }else{
      // Often the key already exists in a set this project just isn't using.
      // Offering that set beats asking for the value again.
      const src=sourceFor(n.name);
      list.append(h("span",{class:"need missing",title:(src?src.set.label+" has it":"not in any of your sets")+(site?" · read in "+site:""),hidden:i>=LIMIT},icon("alert"),n.name,
        src?h("button",{type:"button","aria-label":"Use "+src.set.label+" here, which has "+n.name,onclick:function(){useHere(src.link,src.set.label,true)}},"Use "+src.set.label)
          :h("button",{type:"button","aria-label":"Add "+n.name,onclick:function(){addSecretDialog({key:n.name})}},"Add")));
    }
  });
  card.append(list);
  if(sorted.length>LIMIT){
    card.append(h("button",{type:"button",class:"linkbtn",style:"margin-top:10px",onclick:function(ev){
      [].forEach.call(list.children,function(c){c.hidden=false});ev.currentTarget.remove()}},"Show all "+sorted.length));
  }
  return card;
}

function offersCard(title,lead,rows){
  if(!rows.length)return null;
  const box=h("div",{class:"card"});
  rows.forEach(function(r){box.append(r)});
  return h("section",{class:"section"},h("div",{class:"sechead"},h("div",null,h("h2",{text:title}),h("p",{text:lead}))),box);
}
function offerRow(where,set,link){
  const sample=set.keys.slice(0,6).join(", ")+(set.keys.length>6?", …":"");
  return h("div",{class:"offer"},
    h("div",{class:"what"},h("b",{text:set.label}),h("div",{text:(set.description?set.description+" · ":"")+(set.keys.length?sample:"no keys yet")})),
    h("span",{class:"badge"},plural(set.keys.length,"key")),
    set.usableHere===false
      ?h("button",{type:"button",class:"btn sm",disabled:true,title:"Only for "+set.onlyIn.join(", ")},"Other folders only")
      :h("button",{type:"button",class:"btn sm",onclick:function(){useHere(link,set.label,true)}},icon("plus"),"Use here"));
}

/** Two things a project uses that give the same key: which one wins, and a way to switch. */
function conflictsBanner(all){
  const by={};
  all.forEach(function(u){provides(u).forEach(function(p){(by[p.key]=by[p.key]||[]).push({link:u.link,label:p.label,from:p.from})})});
  const pairs={};
  Object.keys(by).sort().forEach(function(k){
    const list=by[k];
    const w=list[list.length-1];
    // The same value reached two ways (a key, and the set or group it is in) is no conflict.
    const losers=list.slice(0,-1).filter(function(x){return x.link!==w.link&&x.from!==w.from});
    if(!losers.length)return;
    const sig=w.link+"|"+losers.map(function(x){return x.link}).join(",");
    (pairs[sig]=pairs[sig]||{w:w,losers:losers,keys:[]}).keys.push(k);
  });
  const sigs=Object.keys(pairs);
  if(!sigs.length)return null;
  const lines=h("div",{class:"stack",style:"gap:6px"});
  sigs.forEach(function(sig){
    const p=pairs[sig];
    const other=p.losers[p.losers.length-1];
    lines.append(h("div",null,h("b",{text:p.w.label})," wins for ",h("span",{class:"mono",text:p.keys.join(", ")}),
      " over "+p.losers.map(function(x){return x.label}).join(" and ")+". ",
      h("button",{type:"button",class:"linkbtn",onclick:function(){letWin(other.link,other.label)}},"Let "+other.label+" win")));
  });
  return h("div",{class:"banner",style:"margin-bottom:14px"},icon("info"),lines);
}

/** A whole global group this project uses: every set in it, with its keys. */
function groupCard(u,win){
  const g=u.group;
  const card=h("article",{class:"card set","aria-label":g.label},
    h("div",{class:"top"},
      h("div",{class:"title"},icon("folder"),h("b",{text:g.label}),h("span",{class:"badge ok"},"Global group"),h("span",{class:"count",text:plural(u.sets.length,"set")})),
      h("div",{class:"tools"},moreButton("More for "+g.label,function(){return [
        {label:"Stop using here",run:function(){useHere(u.link,g.label,false)}},
      ]}))));
  card.append(h("div",{class:"desc",text:"Every set in the group, including ones you put in it later."}));
  u.sets.forEach(function(set){
    const keys=h("div",{class:"keys"});
    (set.secrets||[]).forEach(function(s){keys.append(keyRow("library",set,s,win,u.link))});
    card.append(h("div",{class:"subset"},
      h("div",{class:"subhead"},h("b",{text:set.label}),h("span",{class:"count",text:plural(set.keys.length,"key")}),
        moreButton("More for "+set.label,function(){return [
          set.name==="default"?null:{label:"Keep for "+folderName()+" only",run:function(){place({action:"here",set:set.name})}},
          {label:"Use in a project…",run:function(){giveKeyDialog({kind:"set",set:set.name})}},
        ]})),
      keys));
  });
  return card;
}

function renderProject(page){
  const fstate=S.folder.state;
  const name=folderName();
  page.append(h("header",{class:"head"},
    h("div",null,h("h1",{text:name}),h("p",{text:fstate==="unset"
      ?"hush hasn't been set up here. Nothing is written until you choose."
      :"What "+name+" gets when you run it with hush — hush dev, hush run, or your agent's hush_run."})),
    h("div",{class:"actions"},
      dropCard(),
      h("button",{type:"button",class:"btn primary",onclick:function(){addSecretDialog()}},icon("plus"),"Add secret"))));

  if(fstate==="unset"){page.append(setupPanel());return}

  const oc=onboardingCard();
  if(oc)page.append(oc);

  const nc=needsCard();
  if(nc)page.append(nc);

  const all=usedSets();
  const win=winners();
  const cb=conflictsBanner(all);
  if(cb)page.append(cb);

  // Its own: kept for it in your library, or in its repository's vault.
  const own=all.filter(function(u){return u.set&&!u.keyLink&&!u.placeholder&&isOwn(u.where,u.set)&&!(u.where==="project"&&u.set.name==="default"&&!u.set.keys.length)});
  const ownSec=h("section",{class:"section"},
    h("div",{class:"sechead"},
      h("div",null,h("h2",{text:"Only "+name}),h("p",{text:"Its own keys, kept for "+name+" alone: hush refuses them anywhere else. Make one global to use it in other projects too."})),
      h("button",{type:"button",class:"btn sm",onclick:function(){newSetDialog("own")}},icon("plus"),"New set")));
  if(own.length){
    const stack=h("div",{class:"stack"});
    own.forEach(function(u){stack.append(setCard(u.where,u.set,{here:true,winners:win,link:u.link}))});
    ownSec.append(stack);
  }else{
    ownSec.append(h("div",{class:"card"},h("div",{class:"offer"},
      h("div",{class:"what"},h("b",null,"No keys of its own yet"),h("div",{text:"A key only "+name+" needs goes here: yours alone, never in its repository."})),
      h("button",{type:"button",class:"btn sm",onclick:function(){addSecretDialog()}},icon("plus"),"Add a key"),
      h("button",{type:"button",class:"btn sm ghost",onclick:function(){DROP_WHERE="own";document.getElementById("picker").click()}},icon("upload"),"Import .env"))));
  }
  page.append(ownSec);

  // From your global keys: groups, sets and single keys.
  const fromGlobal=all.filter(function(u){return u.missing||u.group||u.keyLink||(u.set&&u.where==="library"&&!u.set.own)});
  const gSec=h("section",{class:"section"},
    h("div",{class:"sechead"},h("div",null,h("h2",{text:"From your global keys"}),
      h("p",{text:fromGlobal.length?"Kept once for any project you give them to: rotating one updates them all. Nothing is in "+name+"'s repository."
        :"None yet. Drag a key, a set or a whole group from Global keys on the right onto this project."}))));
  const gStack=h("div",{class:"stack"});
  const singles=h("div",{class:"card list"});
  let singleCount=0;
  fromGlobal.forEach(function(u){
    if(u.missing){
      gStack.append(h("div",{class:"banner warn"},icon("alert"),h("span",null,"This project uses ",h("b",{text:u.missing}),", which isn't in your global keys. Teammates each supply their own copy. ",
        h("button",{type:"button",class:"linkbtn",onclick:function(){useHere(u.link,u.missing,false)}},"Stop using it"))));
      return;
    }
    if(u.group){gStack.append(groupCard(u,win));return}
    if(u.keyLink){
      const s=u.set.secrets[0];
      const k=u.set.label;
      singleCount++;
      singles.append(h("div",{class:"li"},icon("key"),
        h("div",{class:"body"},h("div",{class:"t mono",text:k}),h("div",{class:"d",text:"One key from your global "+u.fromSet.label+(s?" · "+s.preview:"")})),
        h("button",{type:"button",class:"btn sm ghost",onclick:async function(){
          const r=await api("/api/unassign",{project:currentRoot(),link:u.link});
          HUB={projects:r.projects,hidden:r.hidden,crawl:r.crawl,roots:r.roots,rootsChosen:r.rootsChosen,platform:r.platform};await refresh(r.state);toast(k+" is no longer part of "+name);
        }},"Remove"),
        moreButton("More for "+k,function(){return [
          {label:"Keep for "+name+" only",run:function(){place({action:"here",set:u.fromSet.name,key:k})}},
          {label:"Use in another project…",run:function(){giveKeyDialog({kind:"key",set:u.fromSet.name,key:k})}},
        ]})));
      return;
    }
    gStack.append(setCard("library",u.set,{here:true,winners:win,link:u.link}));
  });
  if(singleCount)gStack.append(singles);
  if(fromGlobal.length)gSec.append(gStack);
  page.append(gSec);

  const unusedOwn=S.library.filter(function(s){return s.own&&S.used.indexOf(linkOf(s))<0}).map(function(s){return offerRow("library",s,linkOf(s))})
    .concat(S.project.filter(function(s){return S.used.indexOf(s.name)<0}).map(function(s){return offerRow("project",s,s.name)}));
  add(page,offersCard("Its other sets","Kept for this project, but not applied when it runs.",unusedOwn));

  // Only the global sets that hold something this project's code is missing.
  // Offering every set you own on every project read as "not assigned".
  const lacking=(S.needs||[]).filter(function(n){return !win[n.name]}).map(function(n){return n.name});
  const lib=globalSets().filter(function(s){return S.used.indexOf(linkOf(s))<0});
  const helpful=lib.filter(function(s){return s.keys.some(function(k){return lacking.indexOf(k)>-1})});
  if(S.global.exists&&helpful.length){
    add(page,offersCard("Your global keys can fill these in","Sets that hold something this project's code reads and doesn't have yet.",helpful.map(function(s){return offerRow("library",s,linkOf(s))})));
  }
}

/**
 * A folder hush has never been used in: what its code reads, which of your
 * library sets cover that, and the choice to use them. Nothing is written
 * until the button.
 */
function setupPanel(){
  const sug=S.suggestion||{needed:[],files:0,picks:[],ambiguous:[],uncovered:[],provider:{}};
  const card=h("section",{class:"card pad","aria-label":"Set up"});
  card.append(h("h3",{text:"This folder isn't set up for hush yet"}));
  card.append(h("p",{class:"lead",text:sug.needed.length
    ?"Its code reads "+plural(sug.needed.length,"variable")+" across "+plural(sug.files,"file")+". Pick where they come from."
    :"No environment variables were found in its code. Pick sets from your library, or add a secret."}));

  const checks={};
  const radios={};
  if(globalSets().length){
    const box=h("div",{class:"card",style:"margin-top:14px"});
    globalSets().forEach(function(set){
      const covered=Object.keys(sug.provider).filter(function(k){return sug.provider[k]===set.name});
      // Kept for other folders: shown, so it is not a mystery, but not offered.
      const here=set.usableHere!==false;
      const cb=h("input",{type:"checkbox",checked:here&&sug.picks.indexOf(set.name)>-1,disabled:!here,"aria-label":"Use "+set.label+" here"});
      cb.onchange=sync;
      if(here)checks[set.name]=cb;
      box.append(h("label",{class:"offer",style:here?"cursor:pointer":"opacity:.55"},cb,
        h("div",{class:"what"},h("b",{text:set.label}),h("div",{text:!here?"only for "+set.onlyIn.join(", "):covered.length?"covers "+covered.join(", "):(set.description||set.keys.join(", ")||"no keys yet")})),
        covered.length?h("span",{class:"badge ok"},covered.length+" needed"):h("span",{class:"badge"},plural(set.keys.length,"key"))));
    });
    card.append(box);
  }else{
    card.append(h("div",{class:"banner",style:"margin-top:14px"},icon("info"),h("span",{text:"You have no global keys yet. Import a .env or add a secret — hush keeps it for this project, encrypted, never in its repository."})));
  }
  sug.ambiguous.forEach(function(a){
    const g=h("div",{class:"seg",role:"radiogroup","aria-label":a.key});
    radios[a.key]=g;
    a.options.forEach(function(opt){
      const set=S.library.find(function(x){return x.name===opt});
      g.append(h("label",null,h("input",{type:"radio",name:"amb-"+a.key,value:opt,onchange:sync}),h("span",{text:set?set.label:opt})));
    });
    card.append(h("div",{class:"row",style:"margin-top:12px;align-items:center"},h("span",{class:"mono",text:a.key}),h("span",{class:"muted",text:"is in more than one set:"}),g));
  });
  if(sug.uncovered.length){
    card.append(h("p",{class:"muted",style:"margin:12px 0 0"},"Not in your library yet: ",h("span",{class:"mono",text:sug.uncovered.join(", ")}),". Add them after setup."));
  }
  const agent=h("input",{type:"checkbox"});
  // Nothing to pick from: lead with the two ways a first key gets in.
  if(!globalSets().length){
    card.append(h("div",{style:"display:flex;gap:8px;flex-wrap:wrap;margin-top:18px"},
      h("button",{type:"button",class:"btn primary",onclick:function(){document.getElementById("picker").click()}},icon("upload"),"Import a .env"),
      h("button",{type:"button",class:"btn",onclick:function(){addSecretDialog({target:"own|"})}},icon("plus"),"Add one secret")));
    return card;
  }
  card.append(h("label",{class:"check",style:"margin-top:16px"},agent,h("span",null,h("b",null,"An AI agent will use secrets here"),h("br"),
    h("span",{class:"muted",text:"Every run asks you first, and the agent can't read a value. You can change this later."}))));
  const go=h("button",{type:"submit",class:"btn primary"},"Use these here");
  function chosen(){
    const use=[];
    Object.keys(checks).forEach(function(n){if(checks[n].checked)use.push(n)});
    Object.keys(radios).forEach(function(k){const c=radios[k].querySelector("input:checked");if(c&&use.indexOf(c.value)<0)use.push(c.value)});
    return use;
  }
  function sync(){const n=chosen().length;go.disabled=!n;go.textContent=n?"Use "+plural(n,"set")+" here":"Use these here"}
  const form=h("form",{style:"display:flex;gap:8px;flex-wrap:wrap;margin-top:18px"},go,
    h("button",{type:"button",class:"btn",onclick:function(){document.getElementById("picker").click()}},icon("upload"),"Import .env instead"),
    h("button",{type:"button",class:"btn ghost",onclick:function(){addSecretDialog({target:"own|"})}},"Add one secret"));
  form.onsubmit=async function(ev){
    ev.preventDefault();
    const use=chosen();if(!use.length)return;
    await refresh(await api("/api/setup",{use:use,agent:agent.checked}));
    toast(S.folder.state!=="unset"?"this folder now uses "+plural(use.length,"set"):"saved");
  };
  card.append(form);
  sync();
  return card;
}

/* ---------------------------------------------------------------- library */

/* Global sets only one project uses (GET-like /api/tidy): null until asked, then the list. */
let TIDY=null;
function tidyBanner(){
  if(TIDY===null){
    TIDY="asking";
    api("/api/tidy",{action:"list"}).then(function(r){TIDY=r.offers;if(route()==="library"&&TIDY.length)render()},function(){TIDY=[]});
    return null;
  }
  if(!Array.isArray(TIDY)||!TIDY.length)return null;
  return h("div",{class:"banner",style:"margin-bottom:14px"},icon("info"),
    h("span",null,plural(TIDY.length,"global set")+(TIDY.length===1?" is":" are")+" used by one project only — most likely "+(TIDY.length===1?"that project's":"each project's")+" own. ",
      h("button",{type:"button",class:"linkbtn",onclick:tidyDialog},"Review")));
}
function tidyDialog(){
  const rows=TIDY.map(function(o){return {o:o,cb:h("input",{type:"checkbox",checked:true})}});
  const list=h("div",{class:"card list"});
  rows.forEach(function(r){
    list.append(h("label",{class:"offer",style:"cursor:pointer"},r.cb,
      h("div",{class:"what"},h("b",{text:r.o.label}),h("div",{text:"only "+r.o.name+" uses it · "+plural(r.o.keys,"key")}))));
  });
  dialog({title:"Keep these for the one project using each?",
    lead:"Each is used by one project and no other — most likely imported before keys could belong to one project. Kept for its project, it leaves your global keys and hush refuses it anywhere else. That project keeps getting it, and nothing is deleted.",
    submit:"Keep them there",body:[list],
    onSubmit:async function(){
      const picks=rows.filter(function(r){return r.cb.checked}).map(function(r){return {set:r.o.set,root:r.o.root}});
      if(!picks.length){toast("nothing ticked");return false}
      const r=await api("/api/tidy",{action:"apply",picks:picks});
      await refresh(r);toast("kept "+plural(r.done.length,"set")+" for "+(r.done.length===1?"its project":"their projects"));
    }});
}

function renderLibrary(page){
  const sets=globalSets();
  page.append(h("header",{class:"head"},
    h("div",null,h("h1",null,"Global keys"),h("p",{text:"Yours alone, kept once, never in a repository. Drag a key, a set or a whole group onto any project; rotating a key updates every project that uses it."})),
    h("div",{class:"actions"},
      h("button",{type:"button",class:"btn",onclick:function(){DROP_WHERE="library";document.getElementById("picker").click()}},icon("upload"),"Import .env"),
      sets.length>1?h("button",{type:"button",class:"btn",onclick:function(){newGroupDialog()}},icon("folder"),"New group"):null,
      h("button",{type:"button",class:"btn",onclick:function(){newSetDialog("library")}},icon("plus"),"New set"),
      h("button",{type:"button",class:"btn primary",onclick:function(){addSecretDialog({target:"library|default"})}},icon("key"),"Save a global key"))));
  if(S.global.error){page.append(h("div",{class:"banner warn"},icon("alert"),h("span",{text:S.global.error})));return}
  if(!S.global.exists||!sets.length){
    const others=S.global.others||[];
    page.append(h("div",{class:"card"},h("div",{class:"empty"},
      h("h3",null,S.global.exists?"No global keys yet":"You don't have a library yet"),
      h("p",{text:"Keep a key once — your personal OpenAI key, a client's Stripe account — and add it to any project in one drag. Rotating it is one edit."}),
      h("div",{class:"actions"},
        h("button",{type:"button",class:"btn primary",onclick:function(){newSetDialog("library")}},icon("plus"),"Create a set"),
        h("button",{type:"button",class:"btn",onclick:function(){DROP_WHERE="library";document.getElementById("picker").click()}},icon("upload"),"Import a .env"),
        others.map(function(v){return h("button",{type:"button",class:"btn ghost",onclick:async function(){await refresh(await api("/api/global",{name:v}));toast("your library is now "+v)}},"Use my “"+v+"” vault")})))));
    return;
  }
  add(page,tidyBanner());
  (S.groups||[]).forEach(function(g){
    const members=g.sets.map(function(n){return sets.find(function(x){return x.name===n})}).filter(Boolean);
    const stack=h("div",{class:"stack"});
    members.forEach(function(set){stack.append(setCard("library",set,{useToggle:true}))});
    const head=h("div",{class:"sechead"},
      h("div",null,h("h2",null,icon("folder")," ",g.label),h("p",{text:plural(members.length,"set")+". Drag the group onto a project and it gets every set in it, including ones you put in later."})),
      h("div",{class:"tools"},
        S.folder.state!=="unset"?h("button",{type:"button",class:"btn sm"+(g.used?" on":""),onclick:function(){useHere(g.link,g.label,!g.used)}},g.used?[icon("check"),"Used here"]:"Use here"):null,
        moreButton("More for "+g.label,function(){return groupMenu(g)})));
    draggable(head,{kind:"group",group:g.name});
    page.append(h("section",{class:"section"},head,stack));
  });
  const loose=sets.filter(function(s){return !s.group});
  if(loose.length){
    const stack=h("div",{class:"stack"});
    loose.forEach(function(set){stack.append(setCard("library",set,{useToggle:true}))});
    page.append(h("section",{class:"section"},
      (S.groups||[]).length?h("div",{class:"sechead"},h("div",null,h("h2",{text:"Not in a group"}))):null,stack));
  }
}

/* ------------------------------------------------------------------- team */

function renderTeam(page){
  page.append(h("header",{class:"head"},h("div",null,h("h1",null,"Team",
      S.signed===true?h("span",{class:"badge ok",style:"margin-left:10px;vertical-align:middle"},"signed"):S.signed===false?h("span",{class:"badge",style:"margin-left:10px;vertical-align:middle"},"unsigned"):null),
    h("p",{text:"People who can decrypt this project's vault. Removing someone re-encrypts everything, so their old copy opens nothing new."+(S.signed?" Only an admin can change who is on this list.":"")}))));
  if(S.folder.state!=="vault"){
    page.append(h("div",{class:"banner"},icon("info"),h("span",{text:"This project has no vault yet. Adding someone makes one at .hush/vault.json — commit it so they can read it."})));
  }
  if(S.members.length){
    const list=h("div",{class:"card list section"});
    S.members.forEach(function(m){
      const me=m.name===S.me.name;
      list.append(h("div",{class:"li"},h("div",{class:"avatar",text:initials(m.name)}),
        h("div",{class:"body"},h("div",{class:"t"},m.name,me?h("span",{class:"badge"},"you"):null,h("span",{class:"badge"+(m.role==="admin"?" ok":"")},m.role),
          m.kind==="hardware"?h("span",{class:"badge"},icon("lock"),"hardware key"):null,
          m.ci?h("span",{class:"badge"},"CI"):null),
          h("div",{class:"d mono",text:(m.fingerprint||"").slice(0,16)+(m.sets?"  ·  reads "+(m.sets.join(", ")||"nothing"):"")})),
        me?null:h("button",{type:"button",class:"btn sm ghost dangerous",onclick:function(){
          confirmDialog("Remove "+m.name+"?","Everything is re-encrypted without them. Rotate any key they may have copied at its provider.","Remove",
            async function(){const r=await api("/api/team",{action:"remove",name:m.name});await refresh(r);toast(r.notice||"removed "+m.name)});
        }},"Remove")));
    });
    page.append(list);
  }
  const who=h("input",{class:"input",placeholder:"sam",autocomplete:"off"});
  const pk=h("input",{class:"input mono",placeholder:"hush_pk_… or age1…",autocomplete:"off",spellcheck:"false"});
  // Blank means every set. Names give a scoped member just those (signed vaults).
  const only=h("input",{class:"input",placeholder:"every set",autocomplete:"off"});
  const f=h("form",{class:"row",style:"margin-top:14px"},field("Name",who),field("Their public key",pk),
    S.signed?field("Only these sets",only):null,h("button",{type:"submit",class:"btn primary"},"Give access"));
  f.onsubmit=async function(ev){
    ev.preventDefault();
    if(!who.value.trim()){who.focus();return}
    if(!/^(hush_pk_|age1)/.test(pk.value.trim())){toast("that doesn't look like a public key — it starts with hush_pk_ or age1",{error:true});pk.focus();return}
    const sets=only.value.split(",").map(function(x){return x.trim()}).filter(Boolean);
    const r=await api("/api/team",{name:who.value.trim(),pk:pk.value.trim(),sets:sets});
    await refresh(r);toast(r.vaultCreated?VAULT_MADE:"gave "+who.value.trim()+" access — commit .hush/vault.json");
  };
  page.append(h("section",{class:"card pad section"},h("h3",null,"Add someone"),
    h("p",{class:"lead"},"They run ",h("span",{class:"mono"},"hush id --create")," and send you the key it prints. No invite, no account."),f));
}

`;
