/**
 * The Project, Library and Team sections.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const SECTIONS = String.raw`/* ---------------------------------------------------------------- project */

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
        :"every one is provided.")})),
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
    h("button",{type:"button",class:"btn sm",onclick:function(){useHere(link,set.label,true)}},icon("plus"),"Use here"));
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

  const nc=needsCard();
  if(nc)page.append(nc);

  const used=usedSets();
  const win=winners();
  const sec=h("section",{class:"section"},
    h("div",{class:"sechead"},
      h("div",null,h("h2",{text:"Injected when you run"}),h("p",{text:used.length>1?"Applied top to bottom — when two sets share a key, the lower one wins.":"The sets this project uses."})),
      h("button",{type:"button",class:"btn sm",onclick:function(){newSetDialog("project")}},icon("plus"),"New set")));
  const stack=h("div",{class:"stack"});
  used.forEach(function(u){
    if(u.missing){
      stack.append(h("div",{class:"banner warn"},icon("alert"),h("span",null,"This project uses ",h("b",{text:u.missing}),", which isn't in your library. Teammates each supply their own copy. ",
        h("button",{type:"button",class:"linkbtn",onclick:function(){useHere(u.link,u.missing,false)}},"Stop using it"))));
      return;
    }
    if(u.placeholder){
      stack.append(h("div",{class:"card"},h("div",{class:"offer"},h("div",{class:"ord"},String(u.index+1)),
        h("div",{class:"what"},h("b",null,"default"),h("div",{text:fstate==="links-only"
          ?"This project has no vault of its own yet — the first key you add here makes one."
          :"Keys only this project needs go here."})),
        h("button",{type:"button",class:"btn sm",onclick:function(){addSecretDialog({target:"project|default"})}},icon("plus"),"Add key"))));
      return;
    }
    stack.append(setCard(u.where,u.set,{order:{index:u.index},winners:win,link:u.link}));
  });
  sec.append(stack);
  page.append(sec);

  const unusedProject=S.project.filter(function(s){return S.used.indexOf(s.name)<0});
  add(page,offersCard("Other sets in this project","In the vault, but not applied when you run.",unusedProject.map(function(s){return offerRow("project",s,s.name)})));

  const lib=S.library.filter(function(s){return S.used.indexOf(s.name==="default"?"library:default":s.name)<0});
  if(S.global.exists){
    add(page,offersCard("Add from your library","Your own sets. Nothing reaches this project until you add it.",lib.map(function(s){return offerRow("library",s,s.name==="default"?"library:default":s.name)})));
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
  if(S.library.length){
    const box=h("div",{class:"card",style:"margin-top:14px"});
    S.library.forEach(function(set){
      const covered=Object.keys(sug.provider).filter(function(k){return sug.provider[k]===set.name});
      const cb=h("input",{type:"checkbox",checked:sug.picks.indexOf(set.name)>-1,"aria-label":"Use "+set.label+" here"});
      cb.onchange=sync;
      checks[set.name]=cb;
      box.append(h("label",{class:"offer",style:"cursor:pointer"},cb,
        h("div",{class:"what"},h("b",{text:set.label}),h("div",{text:covered.length?"covers "+covered.join(", "):(set.description||set.keys.join(", ")||"no keys yet")})),
        covered.length?h("span",{class:"badge ok"},covered.length+" needed"):h("span",{class:"badge"},plural(set.keys.length,"key"))));
    });
    card.append(box);
  }else{
    card.append(h("div",{class:"banner",style:"margin-top:14px"},icon("info"),h("span",{text:"Your library is empty. Import a .env or add a secret — hush keeps it in this project, encrypted."})));
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
  if(!S.library.length){
    card.append(h("div",{style:"display:flex;gap:8px;flex-wrap:wrap;margin-top:18px"},
      h("button",{type:"button",class:"btn primary",onclick:function(){document.getElementById("picker").click()}},icon("upload"),"Import a .env"),
      h("button",{type:"button",class:"btn",onclick:function(){addSecretDialog({target:"project|default"})}},icon("plus"),"Add one secret")));
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
    h("button",{type:"button",class:"btn ghost",onclick:function(){addSecretDialog({target:"project|default"})}},"Add one secret"));
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

function renderLibrary(page){
  page.append(h("header",{class:"head"},
    h("div",null,h("h1",null,"Library"),h("p",{text:"Yours alone, never in a repo. Any project can add these — nothing reaches one until it does."})),
    h("div",{class:"actions"},
      h("button",{type:"button",class:"btn",onclick:function(){DROP_WHERE="library";document.getElementById("picker").click()}},icon("upload"),"Import .env"),
      h("button",{type:"button",class:"btn primary",onclick:function(){newSetDialog("library")}},icon("plus"),"New set"))));
  if(S.global.error){page.append(h("div",{class:"banner warn"},icon("alert"),h("span",{text:S.global.error})));return}
  if(!S.global.exists||!S.library.length){
    const others=S.global.others||[];
    page.append(h("div",{class:"card"},h("div",{class:"empty"},
      h("h3",null,S.global.exists?"Your library is empty":"You don't have a library yet"),
      h("p",{text:"Keep a key once — your personal OpenAI key, a client's Stripe account — and add it to any project in one click. Rotating it is one edit."}),
      h("div",{class:"actions"},
        h("button",{type:"button",class:"btn primary",onclick:function(){newSetDialog("library")}},icon("plus"),"Create a set"),
        h("button",{type:"button",class:"btn",onclick:function(){DROP_WHERE="library";document.getElementById("picker").click()}},icon("upload"),"Import a .env"),
        others.map(function(v){return h("button",{type:"button",class:"btn ghost",onclick:async function(){await refresh(await api("/api/global",{name:v}));toast("your library is now "+v)}},"Use my “"+v+"” vault")})))));
    return;
  }
  const stack=h("div",{class:"stack"});
  S.library.forEach(function(set){stack.append(setCard("library",set,{useToggle:true,link:set.name==="default"?"library:default":set.name}))});
  page.append(stack);
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
