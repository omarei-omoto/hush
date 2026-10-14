/**
 * Motion, as on tryhush.dev: a revealed value decrypts out of ciphertext and
 * goes back into it, a waiting bar churns, the line under a project's tabs
 * slides to the one you opened, a view rises into place when you open it,
 * and a project card is lit from wherever the pointer is. Nothing moves for
 * someone whose system asks for less motion.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const MOTION = String.raw`
/* ---------------------------------------------------------------- motion -- */

const STILL=!!(window.matchMedia&&matchMedia("(prefers-reduced-motion: reduce)").matches);
/* What ciphertext looks like: the base64 a vault holds. */
const GLYPHS="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function glyphs(n){let s="";for(let i=0;i<n;i++)s+=GLYPHS.charAt(Math.floor(Math.random()*GLYPHS.length));return s}
/* About as much of a value as a bar has room for: the animation spends its time there. */
const IN_VIEW=56;

function stopCipher(el){if(el._cipher){cancelAnimationFrame(el._cipher);el._cipher=0}}
/** el comes to read text, resolving out of ciphertext left to right; then done(). */
function decrypt(el,text,done){
  stopCipher(el);
  const n=Math.min(text.length,IN_VIEW);
  if(STILL||!n){el.textContent=text;if(done)done();return}
  const ms=Math.min(260+n*12,760),t0=performance.now();
  function step(now){
    const p=Math.min((now-t0)/ms,1),k=Math.floor(p*n);
    if(p<1){el.replaceChildren(document.createTextNode(text.slice(0,k)),h("span",{class:"cipher",text:glyphs(n-k)}));el._cipher=requestAnimationFrame(step)}
    else{el._cipher=0;el.textContent=text;if(done)done()}
  }
  el._cipher=requestAnimationFrame(step);
}
/** The way back: el's text goes into ciphertext, right to left; then done(). */
function encrypt(el,done){
  stopCipher(el);
  const text=el.textContent.slice(0,IN_VIEW),n=text.length;
  if(STILL||!n){if(done)done();return}
  const ms=Math.min(160+n*6,380),t0=performance.now();
  function step(now){
    const p=Math.min((now-t0)/ms,1),k=Math.floor((1-p)*n);
    el.replaceChildren(document.createTextNode(text.slice(0,k)),h("span",{class:"cipher",text:glyphs(n-k)}));
    if(p<1)el._cipher=requestAnimationFrame(step);else{el._cipher=0;if(done)done()}
  }
  el._cipher=requestAnimationFrame(step);
}
/** el churns as ciphertext until the function this returns is called, which puts its text back. */
function churn(el){
  const was=el.textContent;
  if(STILL)return function(){};
  const n=Math.max(8,Math.min(was.length,IN_VIEW));
  const t=setInterval(function(){el.textContent=glyphs(n)},70);
  return function(){clearInterval(t);el.textContent=was};
}

/* A view rises into place when it is opened, not each time it redraws. */
let VIEW_SHOWN="";
function entering(page,view){
  const fresh=view!==VIEW_SHOWN;
  VIEW_SHOWN=view;
  page.classList.toggle("enter",fresh&&!STILL);
}

/* The line under a project's tabs slides from the tab you left to the one you opened. */
let TABLINE=null;
function slideTabline(){
  const tabs=document.querySelector("#page .tabs"),on=tabs&&tabs.querySelector("a[aria-current=page]");
  if(!on){TABLINE=null;return}
  const line=h("i",{class:"tabline","aria-hidden":"true"});
  tabs.classList.add("slid");
  tabs.append(line);
  const to={left:on.offsetLeft,width:on.offsetWidth},from=TABLINE||to;
  TABLINE=to;
  line.style.left=from.left+"px";line.style.width=from.width+"px";
  if(STILL||(from.left===to.left&&from.width===to.width))return;
  // Laid out where it was before it moves, or there is nothing to slide from.
  void line.offsetWidth;
  line.style.left=to.left+"px";line.style.width=to.width+"px";
}

/* A project card is lit from wherever the pointer is. */
document.addEventListener("pointermove",function(ev){
  const card=ev.target&&ev.target.closest&&ev.target.closest(".pcard");
  if(!card)return;
  const r=card.getBoundingClientRect();
  card.style.setProperty("--mx",(ev.clientX-r.left)+"px");
  card.style.setProperty("--my",(ev.clientY-r.top)+"px");
},{passive:true});
`;
