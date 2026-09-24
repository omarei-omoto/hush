/**
 * The page `hush ui` serves: one self-contained document, no network, no
 * dependencies. It lives apart from the server (ui.ts) so each can be read on
 * its own.
 *
 * It is organised around what a person came to do, in the order they came to
 * do it:
 *
 *   - Project: does my app have what it needs to run? The code is scanned for
 *     the variables it reads, and each is shown as provided (and by which set)
 *     or missing (with an Add button). Below that, the sets a run gets, in the
 *     order they apply, with every key visible and the one that wins marked.
 *   - Library: the catalog of your own sets. Nothing in it reaches a project
 *     until the project adds it.
 *   - Team, Agent, Activity: who can decrypt, what an agent must ask for, and
 *     what happened, in sentences.
 *
 * Two rules hold everywhere:
 *
 *   - No value reaches this page unless the person clicks Reveal, which goes
 *     through the same approval as `hush get`. Everything else is a masked
 *     preview built server-side.
 *   - The DOM is built with h(), which only ever sets textContent and
 *     attributes. Nothing assigns HTML built from data, so nothing a vault,
 *     a dropped file or the audit log contains can become markup.
 *
 * This is a String.raw template: the script inside it must not use backticks
 * or the dollar-brace sequence.
 */
export const PAGE = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>hush</title>
<style>
:root{
  --bg:#F5F6F8; --surface:#FFFFFF; --sunken:#F0F2F5; --ink:#101828; --ink-2:#344054; --muted:#667085;
  --line:#E4E7EC; --line-2:#D0D5DD; --brand:#14213D; --brand-ink:#FFFFFF;
  --bar:#14213D; --bar-ink:#C9D1E3;
  --ok:#067647; --ok-bg:#ECFDF3; --warn:#B54708; --warn-bg:#FFFAEB; --danger:#B42318; --danger-bg:#FEF3F2;
  --focus:#3B5BDB; --shadow:0 1px 2px rgba(16,24,40,.05); --shadow-lg:0 16px 40px rgba(16,24,40,.18);
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,Roboto,"Helvetica Neue",sans-serif;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0C0F14; --surface:#141922; --sunken:#1B2130; --ink:#E9EDF3; --ink-2:#C5CCD8; --muted:#8E98AA;
  --line:#252D3B; --line-2:#323C4D; --brand:#E9EDF3; --brand-ink:#0C0F14;
  --bar:#2A3242; --bar-ink:#AEB8CA;
  --ok:#47CD89; --ok-bg:rgba(71,205,137,.12); --warn:#F5B546; --warn-bg:rgba(245,181,70,.12);
  --danger:#F97066; --danger-bg:rgba(249,112,102,.12); --focus:#8DA2FF;
  --shadow:none; --shadow-lg:0 16px 40px rgba(0,0,0,.5);
  color-scheme:dark;
}}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--ink);font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
button,input,select,textarea{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
[hidden]{display:none!important}
.mono{font-family:var(--mono)}
.muted{color:var(--muted)}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
svg.i{width:16px;height:16px;flex:0 0 auto;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}

/* ------------------------------------------------------------------ shell */
.app{display:grid;grid-template-columns:248px minmax(0,1fr);min-height:100vh;
  background:linear-gradient(to right,var(--surface) 247px,var(--line) 247px 248px,transparent 248px)}
.side{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:20px;padding:18px 14px}
.brand{display:flex;align-items:center;gap:9px;padding:0 6px;font-weight:650;font-size:16px;letter-spacing:-.01em}
.brand svg{width:24px;height:24px}
.here{padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg)}
.here .name{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.here .state{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12.5px;margin-top:2px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--muted);flex:0 0 auto}
.dot.ok{background:var(--ok)}.dot.warn{background:var(--warn)}
.nav{display:flex;flex-direction:column;gap:2px}
.nav a{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;color:var(--ink-2);text-decoration:none;font-weight:500}
.nav a:hover{background:var(--sunken);color:var(--ink)}
.nav a[aria-current=page]{background:var(--sunken);color:var(--ink);font-weight:600}
.nav .count{margin-left:auto;font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.nav .count.warn{color:var(--warn);font-weight:600}
.level{margin-top:auto;display:block;padding:12px;border:1px solid var(--line);border-radius:10px;text-decoration:none;color:inherit}
.level:hover{border-color:var(--line-2)}
.level .t{display:flex;justify-content:space-between;font-size:12.5px;color:var(--muted)}
.level .t b{color:var(--ink);font-weight:600}
.meter{display:flex;gap:3px;margin-top:8px}
.meter i{flex:1;height:5px;border-radius:3px;background:var(--line)}
.meter i.on{background:var(--ok)}
.main{min-width:0;padding:32px 40px 96px}
.page{max-width:1040px;margin:0 auto}
.head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.head h1{margin:0;font-size:22px;line-height:1.25;font-weight:650;letter-spacing:-.015em}
.head p{margin:4px 0 0;color:var(--muted);max-width:62ch}
.head .actions{display:flex;gap:8px;flex-wrap:wrap}
.section{margin-top:28px}
.sechead{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;margin-bottom:10px;flex-wrap:wrap}
.sechead h2{margin:0;font-size:15px;font-weight:600}
.sechead p{margin:2px 0 0;color:var(--muted);font-size:13px}
.stack{display:flex;flex-direction:column;gap:12px}

/* ---------------------------------------------------------------- buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:34px;padding:0 13px;
  border:1px solid var(--line-2);border-radius:8px;background:var(--surface);color:var(--ink);
  font-weight:500;cursor:pointer;white-space:nowrap;box-shadow:var(--shadow)}
.btn:hover{background:var(--sunken)}
.btn:disabled{opacity:.5;cursor:default}
.btn.primary{background:var(--brand);border-color:var(--brand);color:var(--brand-ink)}
.btn.primary:hover{opacity:.92}
.btn.danger{background:var(--danger);border-color:var(--danger);color:#fff}
.btn.sm{height:28px;padding:0 10px;font-size:13px;border-radius:7px}
.btn.ghost{background:none;border-color:transparent;box-shadow:none}
.btn.ghost:hover{background:var(--sunken)}
.btn.ghost.dangerous{color:var(--danger)}
.btn.on{color:var(--ok);border-color:transparent;background:var(--ok-bg);box-shadow:none}
.iconbtn{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border:0;border-radius:7px;
  background:none;color:var(--ink-2);cursor:pointer}
.iconbtn:hover{background:var(--sunken);color:var(--ink)}
.iconbtn:disabled{opacity:.35;cursor:default;background:none}
.linkbtn{background:none;border:0;padding:0;color:var(--ink-2);text-decoration:underline;text-underline-offset:2px;cursor:pointer}

/* ------------------------------------------------------------------ forms */
.field{display:flex;flex-direction:column;gap:5px;min-width:0}
.field>span{font-size:12.5px;font-weight:500;color:var(--ink-2)}
.field small{color:var(--muted);font-size:12px}
.input,select.input,textarea.input{height:34px;padding:0 10px;border:1px solid var(--line-2);border-radius:8px;
  background:var(--surface);min-width:0;width:100%}
textarea.input{height:auto;min-height:96px;padding:8px 10px;font-family:var(--mono);font-size:13px;resize:vertical}
.input.mono{font-family:var(--mono);font-size:13px}
.input:focus{outline:2px solid var(--focus);outline-offset:0;border-color:transparent}
.row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}
.row>.field{flex:1 1 180px}
.check{display:flex;align-items:flex-start;gap:9px;cursor:pointer}
.check input{margin:3px 0 0;accent-color:var(--brand)}
.seg{display:inline-flex;align-self:flex-start;padding:3px;border-radius:9px;background:var(--sunken);gap:2px}
.seg label{position:relative;cursor:pointer}
.seg input{position:absolute;opacity:0;inset:0;cursor:pointer}
.seg span{display:block;padding:5px 12px;border-radius:7px;font-weight:500;color:var(--muted);font-size:13px}
.seg input:checked+span{background:var(--surface);color:var(--ink);box-shadow:0 1px 2px rgba(16,24,40,.12)}
.seg input:focus-visible+span{outline:2px solid var(--focus)}
.switch{position:relative;width:36px;height:20px;flex:0 0 auto}
.switch input{position:absolute;inset:0;opacity:0;margin:0;cursor:pointer;z-index:1}
.switch i{position:absolute;inset:0;border-radius:10px;background:var(--line-2);transition:background .15s}
.switch i::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;
  box-shadow:0 1px 2px rgba(0,0,0,.2);transition:transform .15s}
.switch input:checked+i{background:var(--ok)}
.switch input:checked+i::after{transform:translateX(16px)}
.switch input:focus-visible+i{outline:2px solid var(--focus);outline-offset:2px}

/* ------------------------------------------------------------------ cards */
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}
.card.pad{padding:18px 20px}
.card h3{margin:0;font-size:15px;font-weight:600}
.card .lead{margin:4px 0 0;color:var(--muted)}
.banner{display:flex;gap:10px;align-items:flex-start;padding:11px 14px;border-radius:10px;font-size:13.5px;background:var(--sunken);color:var(--ink-2)}
.banner.warn{background:var(--warn-bg);color:var(--warn)}
.banner.ok{background:var(--ok-bg);color:var(--ok)}
.banner svg{margin-top:2px}
.badge{display:inline-flex;align-items:center;gap:4px;height:20px;padding:0 7px;border-radius:6px;font-size:11.5px;font-weight:600;
  background:var(--sunken);color:var(--ink-2);white-space:nowrap}
.badge.ok{background:var(--ok-bg);color:var(--ok)}
.badge.warn{background:var(--warn-bg);color:var(--warn)}
.empty{padding:28px 20px;text-align:center;color:var(--muted)}
.empty h3{color:var(--ink);margin-bottom:4px}
.empty .actions{display:flex;gap:8px;justify-content:center;margin-top:14px;flex-wrap:wrap}

/* -------------------------------------------------------- what code reads */
.needs{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.need{display:inline-flex;align-items:center;gap:6px;height:28px;padding:0 4px 0 9px;border-radius:7px;border:1px solid var(--line);
  font-family:var(--mono);font-size:12.5px;background:var(--surface)}
.need svg{width:14px;height:14px}
.need.ok{color:var(--ink-2)}
.need.ok svg{color:var(--ok)}
.need.missing{border-color:transparent;background:var(--warn-bg);color:var(--warn)}
.need .from{font-family:var(--sans);font-size:11.5px;color:var(--muted);padding-right:5px}
.need button{height:22px;padding:0 8px;border:0;border-radius:5px;background:var(--warn);color:#fff;font:600 11.5px var(--sans);cursor:pointer}
.tally{display:flex;gap:6px;flex-wrap:wrap}

/* --------------------------------------------------------------- set card */
.set .top{display:flex;align-items:center;gap:10px;padding:12px 14px 12px 16px}
.ord{width:22px;height:22px;border-radius:50%;background:var(--sunken);color:var(--muted);display:flex;align-items:center;justify-content:center;
  font:600 11.5px var(--mono);flex:0 0 auto}
.set .title{display:flex;align-items:center;gap:8px;min-width:0;flex:1}
.set .title b{font-weight:600;font-size:14.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.set .title .count{color:var(--muted);font-size:12.5px;white-space:nowrap}
.set .desc{padding:0 16px 10px 16px;margin-top:-6px;color:var(--muted);font-size:13px}
.set.ordered .desc{padding-left:48px}
.set .desc em{font-style:normal;color:var(--ink-2)}
.set .tools{display:flex;align-items:center;gap:2px;flex:0 0 auto}
.keys{border-top:1px solid var(--line)}
.krow{display:grid;grid-template-columns:minmax(150px,230px) minmax(0,1fr) auto;gap:12px;align-items:center;padding:8px 14px 8px 16px}
.krow+.krow{border-top:1px solid var(--line)}
.kname{min-width:0}
.kname .k{font-family:var(--mono);font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
.kname .sub{font-size:11.5px;color:var(--muted);display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.krow.over .k{color:var(--muted);text-decoration:line-through;text-decoration-thickness:1px}
.kact{display:flex;align-items:center;gap:2px}
.tag{display:inline-block;padding:0 6px;border-radius:5px;background:var(--sunken);color:var(--ink-2);font-size:11px;line-height:17px}

/* The one memorable element: every value is under a redaction bar, and only
   Reveal lifts it — for fifteen seconds, then it falls back into place. */
.bar{position:relative;height:30px;border-radius:6px;overflow:hidden;min-width:0;max-width:440px}
.bar .masked,.bar .plain{position:absolute;inset:0;display:flex;align-items:center;padding:0 10px;font:12.5px var(--mono);white-space:nowrap;overflow:hidden}
.bar .masked{background:var(--bar);color:var(--bar-ink);transition:transform .2s ease;letter-spacing:.02em}
.bar .plain{background:var(--sunken);color:var(--ink);user-select:all}
.bar.open .masked{transform:translateY(-100%)}
.bar .timer{position:absolute;left:0;bottom:0;height:2px;background:var(--warn);width:0}
.bar.open .timer{animation:drain 15s linear forwards}
@keyframes drain{from{width:100%}to{width:0}}
.bar.wait .masked{animation:pulse 1.2s ease-in-out infinite}
@keyframes pulse{50%{opacity:.6}}
@media (prefers-reduced-motion:reduce){.bar .masked{transition:none}.bar.open .timer,.bar.wait .masked{animation:none}}
.addkey{border-top:1px dashed var(--line);padding:10px 14px 12px 16px}
.addkey form{display:grid;grid-template-columns:minmax(150px,230px) minmax(0,1fr) auto auto;gap:8px;align-items:center}

/* compact rows: sets that could be added */
.offer{display:flex;align-items:center;gap:12px;padding:11px 14px 11px 16px}
.offer+.offer{border-top:1px solid var(--line)}
.offer .what{flex:1;min-width:0}
.offer .what b{font-weight:600}
.offer .what div{font-size:12.5px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ------------------------------------------------------------------ lists */
.list>.li{display:flex;align-items:center;gap:12px;padding:12px 16px}
.list>.li+.li{border-top:1px solid var(--line)}
.li .body{flex:1;min-width:0}
.li .body .t{font-weight:600;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.li .body .d{font-size:13px;color:var(--muted)}
.avatar{width:32px;height:32px;border-radius:50%;background:var(--sunken);color:var(--ink-2);display:flex;align-items:center;justify-content:center;
  font-weight:600;font-size:12.5px;flex:0 0 auto}
.stepicon{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex:0 0 auto;
  border:1.5px solid var(--line-2);color:var(--muted)}
.stepicon.ok{border-color:transparent;background:var(--ok-bg);color:var(--ok)}
.stepicon svg{width:14px;height:14px}
.cmd{display:inline-flex;align-items:center;gap:4px;padding:2px 2px 2px 9px;border-radius:7px;background:var(--sunken);font:12.5px var(--mono);margin-top:6px;max-width:100%}
.cmd code{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* activity */
.day{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin:22px 0 8px}
.ev{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:12px;align-items:center;padding:10px 16px}
.ev+.ev{border-top:1px solid var(--line)}
.ev .kind{width:8px;height:8px;border-radius:50%;background:var(--line-2)}
.ev .kind.use{background:var(--focus)}.ev .kind.read{background:var(--warn)}.ev .kind.deny{background:var(--danger)}.ev .kind.change{background:var(--ok)}
.ev .who{font-size:12px;color:var(--muted);margin-left:6px}
.ev time{font-size:12.5px;color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums}

/* ---------------------------------------------------------- menus/dialogs */
.menu{position:fixed;z-index:60;min-width:190px;padding:5px;border:1px solid var(--line);border-radius:10px;background:var(--surface);box-shadow:var(--shadow-lg)}
.menu button{display:flex;width:100%;align-items:center;gap:9px;padding:7px 10px;border:0;border-radius:7px;background:none;text-align:left;cursor:pointer}
.menu button:hover,.menu button:focus{background:var(--sunken);outline:none}
.menu button.dangerous{color:var(--danger)}
.menu hr{border:0;border-top:1px solid var(--line);margin:5px 2px}
dialog{border:0;padding:0;border-radius:14px;background:var(--surface);color:var(--ink);box-shadow:var(--shadow-lg);width:min(520px,calc(100vw - 32px));max-height:calc(100vh - 48px)}
dialog.wide{width:min(820px,calc(100vw - 32px))}
dialog::backdrop{background:rgba(12,15,20,.45)}
dialog form.dlg{display:flex;flex-direction:column;max-height:calc(100vh - 48px)}
.dlg .dh{padding:20px 22px 0}
.dlg .dh h2{margin:0;font-size:17px;font-weight:650}
.dlg .dh p{margin:4px 0 0;color:var(--muted)}
.dlg .db{padding:18px 22px;overflow:auto;display:flex;flex-direction:column;gap:14px}
.dlg .df{display:flex;justify-content:flex-end;gap:8px;padding:14px 22px;border-top:1px solid var(--line)}
.dlg .df .left{margin-right:auto}
.srow{display:grid;grid-template-columns:auto minmax(120px,210px) minmax(0,1fr) auto;gap:10px;align-items:center;padding:7px 0}
.srow+.srow{border-top:1px solid var(--line)}
.srow .k{font:500 13px var(--mono);overflow:hidden;text-overflow:ellipsis}
.srow .p{font:12px var(--mono);color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.srow.adv{grid-template-columns:auto minmax(120px,190px) minmax(0,1fr) 150px 100px}
.drop{position:fixed;inset:14px;z-index:70;display:none;align-items:center;justify-content:center;flex-direction:column;gap:6px;
  border:2px dashed var(--brand);border-radius:16px;background:color-mix(in srgb,var(--surface) 92%,transparent);pointer-events:none;
  font-size:17px;font-weight:600}
.drop small{font-weight:400;color:var(--muted);font-size:13px}
.drop.on{display:flex}
.toasts{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:80;display:flex;flex-direction:column;gap:8px;align-items:center;pointer-events:none}
.toast{pointer-events:auto;display:flex;align-items:center;gap:12px;padding:9px 10px 9px 14px;border-radius:10px;background:var(--brand);color:var(--brand-ink);
  font-size:13.5px;box-shadow:var(--shadow-lg);max-width:min(560px,90vw)}
.toast.err{background:var(--danger);color:#fff}
.toast button{background:none;border:1px solid currentColor;color:inherit;border-radius:6px;padding:2px 8px;font-size:12.5px;cursor:pointer;opacity:.9}

/* -------------------------------------------------------------- responsive */
@media (max-width:860px){
  .app{grid-template-columns:1fr}
  .app{background:none}
  .side{position:static;height:auto;flex-direction:row;align-items:center;gap:10px;padding:10px 16px;background:var(--surface);border-bottom:1px solid var(--line)}
  .here{flex:1;min-width:0;padding:6px 10px}
  .level{display:none}
  .nav{position:fixed;left:0;right:0;bottom:0;z-index:50;flex-direction:row;gap:0;padding:6px 6px calc(6px + env(safe-area-inset-bottom));
    background:var(--surface);border-top:1px solid var(--line)}
  .nav a{flex:1;flex-direction:column;gap:2px;padding:6px 2px;font-size:11px;border-radius:8px}
  .nav a svg{width:19px;height:19px}
  .nav .count{display:none}
  .main{padding:20px 16px 96px}
  .head .actions{width:100%}
  .head .actions .btn{flex:1}
  .krow{grid-template-columns:minmax(0,1fr) auto;gap:6px 10px}
  .krow .bar{grid-column:1 / -1;grid-row:2}
  .addkey form{grid-template-columns:1fr 1fr}
  .addkey form .input{grid-column:1 / -1}
  .set .desc{padding-left:16px}
  .srow,.srow.adv{grid-template-columns:auto minmax(0,1fr);gap:4px 10px}
  .srow>*{grid-column:2}
  .srow>input[type=checkbox]{grid-column:1;grid-row:1 / span 4;align-self:start;margin-top:3px}
  .srow>.badge{justify-self:start}
  .set .title .count{display:none}
}
</style></head><body>
<div class="app">
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
const T="__TOKEN__";
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

/* --------------------------------------------------------------- actions */

async function setSecret(scope,key,value,where){
  const r=await api("/api/secret",{scope:scope,key:key,value:value,where:where});
  await refresh(r);
  toast(r.vaultCreated?VAULT_MADE:(value===null?"deleted "+key:"saved "+key));
  return r;
}
async function retag(scope,key,note){
  await refresh(await api("/api/tag",{scope:scope,key:key,note:note}));
  toast(note?"tagged "+key:"tag cleared");
}
async function useHere(link,label,use){
  await refresh(await api("/api/link",{name:link,use:use!==false}));
  toast(use===false?"stopped using "+label+" here":label+" is now used here",
    use===false?null:{action:{label:"Undo",run:function(){useHere(link,label,false)}}});
}
async function moveOrder(index,delta){
  const order=S.used.slice();
  const j=index+delta;
  if(j<0||j>=order.length)return;
  const t=order[j];order[j]=order[index];order[index]=t;
  await refresh(await api("/api/link",{order:order}));
}
async function ensureLibrary(){
  if(!S.global.exists){await api("/api/global",{create:true})}
}

/** Add a secret: the one thing people come here to do most. */
function addSecretDialog(prefill){
  prefill=prefill||{};
  const KEY_RE=/^[A-Za-z_][A-Za-z0-9_]*$/;
  const key=h("input",{class:"input mono",placeholder:"STRIPE_SECRET_KEY",autocomplete:"off",spellcheck:"false",value:prefill.key||""});
  key.addEventListener("input",function(){const p=key.selectionStart;key.value=key.value.toUpperCase().replace(/\s+/g,"_");key.setSelectionRange(p,p);check()});
  const single=h("input",{class:"input mono",type:"password",autocomplete:"new-password",spellcheck:"false",placeholder:"paste the value"});
  const multi=h("textarea",{class:"input",spellcheck:"false",placeholder:"-----BEGIN PRIVATE KEY-----",hidden:true});
  const shape=h("button",{type:"button",class:"linkbtn",onclick:function(){
    const toMulti=multi.hidden;multi.hidden=!toMulti;single.hidden=toMulti;
    (toMulti?multi:single).value=(toMulti?single:multi).value;shape.textContent=toMulti?"Single line":"Multi-line value";
    (toMulti?multi:single).focus();
  }},"Multi-line value");
  const reveal=h("button",{type:"button",class:"linkbtn",onclick:function(){single.type=single.type==="password"?"text":"password";reveal.textContent=single.type==="password"?"Show":"Hide"}},"Show");

  // Where it goes: the sets this project uses first, then its other sets, then the library.
  const sel=h("select",{class:"input"});
  const used=usedSets().filter(function(u){return u.set&&!u.placeholder});
  const g1=h("optgroup",{label:"Used here"});
  used.forEach(function(u){g1.append(h("option",{value:u.where+"|"+u.set.name},u.set.label+(u.where==="library"?"  · library":"")))});
  if(!used.some(function(u){return u.where==="project"&&u.set.name==="default"}))g1.append(h("option",{value:"project|default"},"default  · this project"));
  sel.append(g1);
  const others=S.project.filter(function(s){return S.used.indexOf(s.name)<0});
  if(others.length){const g=h("optgroup",{label:"This project"});others.forEach(function(s){g.append(h("option",{value:"project|"+s.name},s.label))});sel.append(g)}
  const lib=S.library.filter(function(s){return S.used.indexOf(s.name==="default"?"library:default":s.name)<0});
  if(lib.length){const g=h("optgroup",{label:"Library"});lib.forEach(function(s){g.append(h("option",{value:"library|"+s.name},s.label))});sel.append(g)}
  sel.append(h("optgroup",{label:"New"},h("option",{value:"new|project"},"New set in this project…"),h("option",{value:"new|library"},"New set in my library…")));
  if(prefill.target)sel.value=prefill.target;
  const newName=h("input",{class:"input",placeholder:"e.g. Stripe live"});
  const newWrap=field("New set name",newName);
  const useIt=h("input",{type:"checkbox",checked:true});
  const useWrap=h("label",{class:"check"},useIt,h("span",null,"Use this set in ",h("b",{text:folderName()})));
  const warn=h("div",{class:"banner warn",hidden:true});
  const note=h("input",{class:"input",placeholder:"e.g. live, read-only, expires June"});

  function target(){const v=sel.value.split("|");return {kind:v[0],where:v[0]==="new"?v[1]:v[0],name:v.slice(1).join("|")}}
  function check(){
    const t=target();
    newWrap.hidden=t.kind!=="new";
    const link=t.kind==="library"?(t.name==="default"?"library:default":t.name):t.name;
    useWrap.hidden=!(t.kind==="new"||(t.kind==="library"&&S.used.indexOf(link)<0)||(t.kind==="project"&&S.used.indexOf(t.name)<0));
    const list=t.where==="library"?S.library:S.project;
    const s=t.kind==="new"?null:list.find(function(x){return x.name===t.name});
    const exists=s&&s.keys.indexOf(key.value)>-1;
    warn.hidden=!exists;
    clear(warn);if(exists)warn.append(icon("alert"),h("span",{text:key.value+" is already in "+s.label+" — saving replaces it."}));
  }
  sel.onchange=check;check();

  dialog({
    title:"Add a secret",
    lead:"Stored encrypted. It never comes back to this page unless you reveal it.",
    submit:"Save secret",
    body:[
      field("Name",key),
      h("div",{class:"field"},h("span",{style:"display:flex;justify-content:space-between"},"Value",h("span",{style:"display:flex;gap:12px;font-weight:400"},reveal,shape)),single,multi),
      field("Save to",sel),newWrap,useWrap,warn,
      field("Tag (optional)",note,"A word to tell values apart, like live or test. Not secret."),
    ],
    onSubmit:async function(){
      const k=key.value.trim();
      const v=multi.hidden?single.value:multi.value;
      if(!KEY_RE.test(k)){toast("a name is letters, digits and _, not starting with a digit",{error:true});key.focus();return false}
      if(!v){toast("paste a value first",{error:true});return false}
      const t=target();
      let where=t.where,scope=t.name;
      if(t.kind==="new"){
        if(!newName.value.trim()){toast("name the new set",{error:true});newName.focus();return false}
        if(where==="library")await ensureLibrary();
        const c=await api("/api/env",{action:"create",where:where,label:newName.value.trim()});
        scope=c.created;
      }else if(where==="library")await ensureLibrary();
      const r=await api("/api/secret",{scope:scope,key:k,value:v,where:where,note:note.value.trim()||undefined});
      let next=r;
      if(!useWrap.hidden&&useIt.checked){
        next=await api("/api/link",{name:where==="library"&&scope==="default"?"library:default":scope,use:true});
      }
      await refresh(next);
      toast(r.vaultCreated?VAULT_MADE:"saved "+k);
    },
  });
}

function newSetDialog(where){
  const name=h("input",{class:"input",placeholder:where==="library"?"e.g. Personal OpenAI":"e.g. Staging"});
  const desc=h("input",{class:"input",placeholder:"Live Stripe and Postgres for deploys"});
  const svc=h("select",{class:"input"},h("option",{value:""},"No — I'll add keys myself"));
  S.catalog.forEach(function(c){svc.append(h("option",{value:c.id},c.label+"  ("+c.vars.join(", ")+")"))});
  const useIt=h("input",{type:"checkbox",checked:where==="project"});
  dialog({
    title:where==="library"?"New set in your library":"New set in this project",
    lead:where==="library"?"Yours alone, on this machine. Any project can add it later."
      :"Committed with the project, so everyone on the team gets it.",
    submit:"Create set",
    body:[field("Name",name),field("What is it for? (optional)",desc,"Your agent reads this to pick the right set."),
      field("For a known service?",svc,"hush asks for exactly the variables it needs."),
      h("label",{class:"check"},useIt,h("span",null,"Use it in ",h("b",{text:folderName()})))],
    onSubmit:async function(){
      const label=name.value.trim();
      if(!label){toast("give it a name",{error:true});name.focus();return false}
      if(where==="library")await ensureLibrary();
      const r=await api("/api/env",{action:"create",where:where,label:label,description:desc.value.trim()||undefined,service:svc.value||undefined});
      let next=r;
      if(useIt.checked)next=await api("/api/link",{name:where==="library"&&r.created==="default"?"library:default":r.created,use:true});
      await refresh(next);
      toast(r.vaultCreated?VAULT_MADE:"created "+label);
      if(r.vars&&r.vars.length)serviceValuesDialog(where,r.created,label,r.vars);
    },
  });
}

function serviceValuesDialog(where,scope,label,vars){
  const inputs=vars.map(function(v){return {key:v,input:h("input",{class:"input mono",type:"password",autocomplete:"new-password",spellcheck:"false"})}});
  dialog({
    title:"Fill in "+label,lead:"Leave any blank to add it later.",submit:"Save values",
    body:inputs.map(function(it){return field(it.key,it.input)}),
    onSubmit:async function(){
      let n=0;
      for(const it of inputs){if(!it.input.value)continue;await api("/api/secret",{where:where,scope:scope,key:it.key,value:it.input.value});n++}
      await refresh();toast("saved "+plural(n,"value"));
    },
  });
}

function editSetDialog(where,set){
  const name=h("input",{class:"input",value:set.label});
  const desc=h("input",{class:"input",value:set.description||"",placeholder:"What is it for?"});
  const when=h("input",{class:"input",value:set.whenToUse||"",placeholder:"e.g. deploys only, never in tests"});
  dialog({
    title:"Edit "+set.label,submit:"Save",
    body:[field("Name",name,set.name==="default"?"":"Renaming re-seals every value under the new name."),
      field("Description",desc),field("When to use it",when,"Shown to your agent when it picks a set.")],
    onSubmit:async function(){
      const label=name.value.trim();
      let next=null;
      if(label&&label!==set.label){next=await api("/api/env",{action:"rename",where:where,name:set.name,label:label})}
      const renamed=next&&next.renamed?next.renamed:set.name;
      if(desc.value!==(set.description||"")||when.value!==(set.whenToUse||"")){
        next=await api("/api/env",{action:"describe",where:where,name:renamed,description:desc.value.trim(),whenToUse:when.value.trim()});
      }
      await refresh(next);toast("saved");
    },
  });
}

function deleteSetDialog(where,set){
  confirmDialog("Delete "+set.label+"?",
    plural(set.keys.length,"key")+" will be gone for good"+(where==="project"?" — for everyone, once you commit.":"."),
    "Delete set",
    async function(){await refresh(await api("/api/env",{action:"delete",where:where,name:set.name}));toast("deleted "+set.label)});
}

function replaceDialog(where,scope,key){
  const v=h("textarea",{class:"input",spellcheck:"false",placeholder:"paste the new value"});
  dialog({
    title:"Replace "+key,lead:"The old value is overwritten. Nothing is shown here.",submit:"Replace",
    body:[field("New value",v)],
    onSubmit:async function(){if(!v.value){toast("paste a value first",{error:true});return false}await setSecret(scope,key,v.value.replace(/\n$/,""),where)},
  });
}

function moveDialog(where,fromSet,key){
  const list=(where==="library"?S.library:S.project).filter(function(x){return x.name!==fromSet.name});
  const sel=h("select",{class:"input"});
  list.forEach(function(s){sel.append(h("option",{value:s.name},s.label))});
  dialog({
    title:"Move "+key,lead:"From "+fromSet.label+". The value is re-sealed under its new set.",submit:"Move",
    body:[field("To",sel)],
    onSubmit:async function(){await refresh(await api("/api/move",{where:where,key:key,from:fromSet.name,to:sel.value}));toast("moved "+key+" to "+setLabel(where,sel.value))},
  });
}

function tagDialog(scope,key,current){
  const t=h("input",{class:"input",value:current||"",placeholder:"e.g. live"});
  dialog({title:"Tag "+key,submit:"Save",body:[field("Tag",t,"Leave empty to clear it.")],
    onSubmit:async function(){await retag(scope,key,t.value.trim())}});
}

/** Reveal: approval may pop up on the desktop first, so the bar says it is waiting. */
async function reveal(where,scope,key,bar,plain,btn){
  if(bar.classList.contains("open")){if(bar._hide)bar._hide();return}
  bar.classList.add("wait");btn.disabled=true;btn.lastChild.textContent="Waiting…";
  bar.setAttribute("aria-busy","true");
  let value;
  try{value=(await api("/api/reveal",{scope:scope,key:key,where:where})).value}
  catch(e){bar.classList.remove("wait");btn.disabled=false;btn.lastChild.textContent="Reveal";bar.removeAttribute("aria-busy");return}
  bar.classList.remove("wait");bar.removeAttribute("aria-busy");
  plain.textContent=value;
  bar.classList.add("open");btn.disabled=false;
  btn.replaceChildren(icon("eyeoff"),document.createTextNode("Hide"));
  const copy=h("button",{type:"button",class:"btn sm ghost",onclick:async function(){
    try{await navigator.clipboard.writeText(value);toast("copied "+key)}catch(e){toast("copying is blocked here — select the text instead",{error:true})}
  }},icon("copy"),"Copy");
  btn.after(copy);
  const timer=setTimeout(hide,15000);
  function hide(){clearTimeout(timer);bar.classList.remove("open");plain.textContent="";copy.remove();
    btn.replaceChildren(icon("eye"),document.createTextNode("Reveal"));}
  bar._hide=hide;
}

/* ------------------------------------------------------------- set cards */

function keyRow(where,set,s,win,link){
  const over=win&&win[s.key]&&win[s.key].link!==link;
  const plain=h("div",{class:"plain"});
  const masked=h("div",{class:"masked",text:s.preview});
  const bar=h("div",{class:"bar",title:over?"not used: "+win[s.key].label+" overrides it":null},plain,masked,h("div",{class:"timer"}));
  const rv=h("button",{type:"button",class:"btn sm ghost","aria-label":"Reveal "+s.key},icon("eye"),"Reveal");
  rv.onclick=function(){reveal(where,set.name,s.key,bar,plain,rv)};
  const sub=[];
  if(s.note)sub.push(h("span",{class:"tag",text:s.note}));
  if(over)sub.push(h("span",{text:"overridden by "+win[s.key].label}));
  return h("div",{class:"krow"+(over?" over":"")},
    h("div",{class:"kname"},h("span",{class:"k",text:s.key,title:s.key}),sub.length?h("div",{class:"sub"},sub):null),
    bar,
    h("div",{class:"kact"},rv,moreButton("More for "+s.key,[
      {label:"Replace value…",run:function(){replaceDialog(where,set.name,s.key)}},
      where==="project"?{label:s.note?"Edit tag…":"Add a tag…",run:function(){tagDialog(set.name,s.key,s.note)}}:null,
      (where==="library"?S.library:S.project).length>1?{label:"Move to another set…",run:function(){moveDialog(where,set,s.key)}}:null,
      "-",
      {label:"Delete "+s.key,danger:true,run:function(){confirmDialog("Delete "+s.key+"?","It is removed from "+set.label+". This cannot be undone.","Delete",function(){return setSecret(set.name,s.key,null,where)})}},
    ])));
}

const OPEN_ADD={};
function addKeyRow(where,set){
  const id=where+":"+set.name;
  const wrap=h("div",{class:"addkey"});
  if(!OPEN_ADD[id]){
    wrap.append(h("button",{type:"button",class:"btn sm ghost",onclick:function(){OPEN_ADD[id]=true;render();
      const k=document.querySelector("[data-add='"+CSS.escape(id)+"'] input");if(k)k.focus()}},icon("plus"),"Add key"));
    return wrap;
  }
  const k=h("input",{class:"input mono",placeholder:"KEY","aria-label":"New key name in "+set.label,autocomplete:"off",spellcheck:"false"});
  k.addEventListener("input",function(){k.value=k.value.toUpperCase().replace(/\s+/g,"_")});
  const v=h("input",{class:"input mono",type:"password",placeholder:"value","aria-label":"Value","autocomplete":"new-password"});
  const f=h("form",{"data-add":id},k,v,h("button",{type:"submit",class:"btn sm primary"},"Add"),
    h("button",{type:"button",class:"btn sm ghost",onclick:function(){delete OPEN_ADD[id];render()}},"Cancel"));
  f.onsubmit=async function(ev){
    ev.preventDefault();
    if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k.value)){toast("a name is letters, digits and _",{error:true});k.focus();return}
    if(!v.value){v.focus();return}
    try{await setSecret(set.name,k.value,v.value,where)}catch(e){}
  };
  f.addEventListener("keydown",function(ev){if(ev.key==="Escape"){delete OPEN_ADD[id];render()}});
  wrap.append(f);
  return wrap;
}

/**
 * One set: its name and where it lives, what it is for, and every key in it.
 * ctx.order adds the position badge and up/down; ctx.useToggle adds the
 * library's use-here button.
 */
function setCard(where,set,ctx){
  ctx=ctx||{};
  const link=ctx.link||set.name;
  const tools=h("div",{class:"tools"});
  if(ctx.order){
    tools.append(h("button",{type:"button",class:"iconbtn","aria-label":"Apply "+set.label+" earlier",disabled:ctx.order.index===0,
      onclick:function(){moveOrder(ctx.order.index,-1)}},icon("up")));
    tools.append(h("button",{type:"button",class:"iconbtn","aria-label":"Apply "+set.label+" later",disabled:ctx.order.index===S.used.length-1,
      onclick:function(){moveOrder(ctx.order.index,1)}},icon("down")));
  }
  if(ctx.useToggle){
    const used=S.used.indexOf(link)>-1;
    tools.append(h("button",{type:"button",class:"btn sm"+(used?" on":""),onclick:function(){useHere(link,set.label,!used)},
      title:used?"Stop using it in "+folderName():null},used?[icon("check"),"Used here"]:"Use here"));
  }
  const floor=where==="project"&&set.name==="default";
  tools.append(moreButton("More for "+set.label,function(){return [
    {label:"Add a key…",run:function(){addSecretDialog({target:where+"|"+set.name})}},
    {label:"Edit name and description…",run:function(){editSetDialog(where,set)}},
    ctx.order&&!floor?{label:"Stop using here",run:function(){useHere(link,set.label,false)}}:null,
    "-",
    floor?null:{label:"Delete set…",danger:true,run:function(){deleteSetDialog(where,set)}},
  ]}));

  const top=h("div",{class:"top"},
    ctx.order?h("div",{class:"ord",title:"Applied in position "+(ctx.order.index+1)},String(ctx.order.index+1)):null,
    h("div",{class:"title"},h("b",{text:set.label}),
      h("span",{class:"badge"},where==="library"?"Library":"Project"),
      h("span",{class:"count",text:plural(set.keys.length,"key")})),
    tools);
  const card=h("article",{class:"card set"+(ctx.order?" ordered":""),"aria-label":set.label},top);
  const bits=[];
  if(set.description)bits.push(set.description);
  if(set.whenToUse)bits.push("Use for: "+set.whenToUse);
  if(floor&&!set.description)bits.push("Always applied first. Keys that only this project needs go here.");
  if(bits.length)card.append(h("div",{class:"desc",text:bits.join(" · ")}));
  if(set.secrets&&set.secrets.length){
    const keys=h("div",{class:"keys"});
    set.secrets.forEach(function(s){keys.append(keyRow(where,set,s,ctx.winners,link))});
    card.append(keys);
  }
  card.append(addKeyRow(where,set));
  return card;
}

/* ---------------------------------------------------------------- project */

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
  page.append(h("header",{class:"head"},h("div",null,h("h1",null,"Team"),
    h("p",{text:"People who can decrypt this project's vault. Removing someone re-encrypts everything, so their old copy opens nothing new."}))));
  if(S.folder.state!=="vault"){
    page.append(h("div",{class:"banner"},icon("info"),h("span",{text:"This project has no vault yet. Adding someone makes one at .hush/vault.json — commit it so they can read it."})));
  }
  if(S.members.length){
    const list=h("div",{class:"card list section"});
    S.members.forEach(function(m){
      const me=m.name===S.me.name;
      list.append(h("div",{class:"li"},h("div",{class:"avatar",text:initials(m.name)}),
        h("div",{class:"body"},h("div",{class:"t"},m.name,me?h("span",{class:"badge"},"you"):null,h("span",{class:"badge"+(m.role==="admin"?" ok":"")},m.role),
          m.kind==="hardware"?h("span",{class:"badge"},icon("lock"),"hardware key"):null),
          h("div",{class:"d mono",text:(m.fingerprint||"").slice(0,16)})),
        me?null:h("button",{type:"button",class:"btn sm ghost dangerous",onclick:function(){
          confirmDialog("Remove "+m.name+"?","Everything is re-encrypted without them. Rotate any key they may have copied at its provider.","Remove",
            async function(){const r=await api("/api/team",{action:"remove",name:m.name});await refresh(r);toast(r.notice||"removed "+m.name)});
        }},"Remove")));
    });
    page.append(list);
  }
  const who=h("input",{class:"input",placeholder:"sam",autocomplete:"off"});
  const pk=h("input",{class:"input mono",placeholder:"hush_pk_… or age1…",autocomplete:"off",spellcheck:"false"});
  const f=h("form",{class:"row",style:"margin-top:14px"},field("Name",who),field("Their public key",pk),h("button",{type:"submit",class:"btn primary"},"Give access"));
  f.onsubmit=async function(ev){
    ev.preventDefault();
    if(!who.value.trim()){who.focus();return}
    if(!/^(hush_pk_|age1)/.test(pk.value.trim())){toast("that doesn't look like a public key — it starts with hush_pk_ or age1",{error:true});pk.focus();return}
    const r=await api("/api/team",{name:who.value.trim(),pk:pk.value.trim()});
    await refresh(r);toast(r.vaultCreated?VAULT_MADE:"gave "+who.value.trim()+" access — commit .hush/vault.json");
  };
  page.append(h("section",{class:"card pad section"},h("h3",null,"Add someone"),
    h("p",{class:"lead"},"They run ",h("span",{class:"mono"},"hush id --create")," and send you the key it prints. No invite, no account."),f));
}

/* ------------------------------------------------------------------ agent */

function copyCmd(text){
  return h("span",{class:"cmd"},h("code",{text:text}),h("button",{type:"button",class:"iconbtn","aria-label":"Copy "+text,onclick:async function(){
    try{await navigator.clipboard.writeText(text);toast("copied")}catch(e){toast("copying is blocked here",{error:true})}}},icon("copy")));
}

function renderAgent(page){
  page.append(h("header",{class:"head"},h("div",null,h("h1",null,"Agent"),
    h("p",{text:"Your coding agent can use these secrets without ever reading one. Here's what it's connected to, and what it has to ask you first."}))));

  const steps=[
    {ok:S.agent.mcpRegistered,t:"Connect hush to your agent",d:"Adds hush's tools to Claude Code, Codex or Cursor — it asks before writing each file.",cmd:"hush install-mcp"},
    {ok:S.agent.skillInstalled,t:"Teach it the rules",d:"A short skill: never ask for a key in chat, pick the right set, open the secure prompt instead.",cmd:"hush install-skill"},
    {ok:S.agent.policyFloorPresent,t:"Optional: a floor this repo can't lower",d:"Rules in ~/.hush/policy.json that apply to every project, whatever its own file says.",cmd:"hush secure"},
  ];
  const list=h("div",{class:"card list"});
  steps.forEach(function(s){
    list.append(h("div",{class:"li",style:"align-items:flex-start"},h("div",{class:"stepicon"+(s.ok?" ok":"")},s.ok?icon("check"):null),
      h("div",{class:"body"},h("div",{class:"t",text:s.t}),h("div",{class:"d",text:s.ok?"Done.":s.d}),s.ok?null:copyCmd(s.cmd))));
  });
  page.append(list);

  const ACTIONS=[
    ["run","Running a command with secrets","hush run, hush dev, and the agent's hush_run. The prompt names the command and the keys."],
    ["request","Sending a secret to an API","hush request and the agent's hush_request."],
    ["reveal","Showing a value","hush get, hush export, and Reveal on this page."],
    ["add","Saving a new secret","So nothing lands in the vault that you didn't see."],
  ];
  const sw=h("div",{class:"card list"});
  ACTIONS.forEach(function(a){
    const cb=h("input",{type:"checkbox",checked:S.policy.requireApproval.indexOf(a[0])>-1,"aria-label":"Ask first: "+a[1]});
    cb.onchange=async function(){
      const next=new Set(S.policy.requireApproval);
      if(cb.checked)next.add(a[0]);else next.delete(a[0]);
      try{S=await api("/api/policy",{requireApproval:Array.from(next)});render();toast(cb.checked?"asks first now":"no longer asks")}
      catch(e){cb.checked=!cb.checked}
    };
    sw.append(h("label",{class:"li",style:"cursor:pointer"},h("div",{class:"body"},h("div",{class:"t",text:a[1]}),h("div",{class:"d",text:a[2]})),
      h("span",{class:"switch"},cb,h("i"))));
  });
  const TTL=[[900,"15 minutes"],[1800,"30 minutes"],[3600,"1 hour"],[14400,"4 hours"],[86400,"all day"]];
  const ttl=h("select",{class:"input",style:"width:auto","aria-label":"How long an Allow lasts"});
  TTL.forEach(function(p){ttl.append(h("option",{value:String(p[0])},p[1]))});
  if(!TTL.some(function(p){return p[0]===S.policy.approvalTtlSeconds})){
    ttl.append(h("option",{value:String(S.policy.approvalTtlSeconds)},Math.round(S.policy.approvalTtlSeconds/60)+" minutes (set by hand)"));
  }
  ttl.value=String(S.policy.approvalTtlSeconds);
  ttl.onchange=async function(){
    try{S=await api("/api/policy",{requireApproval:S.policy.requireApproval,approvalTtlSeconds:Number(ttl.value)});render();toast("saved")}catch(e){}
  };
  sw.append(h("div",{class:"li"},h("div",{class:"body"},h("div",{class:"t"},"An “Allow” lasts"),
    h("div",{class:"d",text:"For your agent's session. A command in your terminal always asks once."})),ttl));

  const how=S.policy.promptAvailable
    ?(S.policy.biometryAvailable&&S.policy.biometry!=="off"?"Prompts use your fingerprint.":"Prompts appear as a dialog on this screen, with a code that also shows in the agent's transcript.")
    :null;
  page.append(h("section",{class:"section"},h("div",{class:"sechead"},h("div",null,h("h2",null,"Ask me first before…"),
    h("p",{text:"Written to .hush/policy.json, so the team gets the same rules. In your own terminal nothing is blocked outright — risky commands just say so in the prompt."}))),
    S.policy.promptAvailable?null:h("div",{class:"banner warn",style:"margin-bottom:12px"},icon("alert"),h("span",{text:"Nothing on this machine can show a prompt (no desktop dialog or fingerprint reader), so anything switched on below is refused."})),
    sw,how?h("p",{class:"muted",style:"font-size:13px;margin:10px 2px 0",text:how}):null));

  const p=S.posture;
  const meter=h("div",{class:"meter",style:"margin:10px 0 12px"});
  for(let i=1;i<=5;i++)meter.append(h("i",{class:i<=p.rung?"on":""}));
  page.append(h("section",{class:"card pad section","aria-label":"Security level"},
    h("div",{class:"sechead",style:"margin:0"},h("div",null,h("h3",null,"How protected this is"),h("p",{class:"lead",text:"Level "+p.rung+" of 5 · "+p.name})),
      p.rung>=5?h("span",{class:"badge ok"},icon("check"),"top level"):null),
    meter,
    p.next?h("div",null,h("div",{style:"font-weight:600"},"Next: "+p.next.label),p.next.why?h("div",{class:"muted",text:p.next.why}):null,
      /^hush /.test(p.next.command)?copyCmd(p.next.command):h("div",{class:"muted mono",style:"font-size:12.5px;margin-top:4px",text:p.next.command})):null));
}

/* --------------------------------------------------------------- activity */

const WHO={cli:"terminal",mcp:"agent",ui:"this app"};
/** A set's name as the person gave it, when the log only has its slug. */
function nm(slug){
  if(!slug||!S)return slug||"";
  const x=S.project.find(function(s){return s.name===slug})||S.library.find(function(s){return s.name===slug});
  return x?x.label:slug;
}
function describeEvent(e){
  const k=e.key||"",set=nm(e.env||e.set||e.scope||"");
  const list=function(v){return Array.isArray(v)?v.join(", "):String(v||"")};
  switch(e.action){
    case "add":
      if(e.kind==="start"||e.file)return ["change","Imported "+plural(Number(e.added)||0,"key")+" from "+(e.file||"a file")+(set?" into "+set:"")];
      if(e.actor==="mcp")return ["change","Agent had you add "+(list(e.stored)||"a secret")+(set?" to "+set:"")];
      return ["change","Added "+(k||list(e.keys)||"a secret")+(set?" to "+set:"")];
    case "set":case "create":return ["change","Saved "+k+(set?" in "+set:"")];
    case "update":return ["change","Changed "+k+(set?" in "+set:"")];
    case "delete":return ["change","Deleted "+k+(set?" from "+set:"")];
    case "add.cancelled":return ["other","You cancelled adding "+list(e.vars)];
    case "reveal":return ["read","Revealed "+(k||"a value")+(String(e.to||"").indexOf("clipboard")===0?" to the clipboard":"")];
    case "export":return ["read","Exported secrets to "+(e.to||"stdout")];
    case "run":return ["use","Ran "+(e.command||"a command")+(e.injected!==undefined?" with "+plural(Number(e.injected),"secret"):"")+(e.exit!==undefined&&e.exit!==0?" · exit "+e.exit:"")];
    case "request":return ["use",(e.method||"Called")+" "+(e.url?String(e.url).replace(/^https?:\/\//,"").split(/[/?]/)[0]:"an API")+(e.status?" · "+e.status:"")];
    case "approval":{
      const d=e.decision==="deny"?"Denied":e.decision==="timeout"?"Nobody answered":"Approved";
      return [e.decision==="deny"||e.decision==="timeout"?"deny":"use",d+" "+(e.on==="run"?"a run":e.on==="request"?"an API call":e.on==="reveal"?"a reveal":e.on==="materialize"?"writing a secret to disk":(e.on||"a request"))+(e.via==="none"&&e.decision==="deny"?" — no prompt available":"")];
    }
    case "import":return ["change","Imported "+plural(Number(e.imported)||0,"key")+(e.skipped?", skipped "+e.skipped:"")];
    case "stage":return ["other","Opened "+(e.file||"a file")+" for review ("+plural(Number(e.keys)||0,"key")+")"];
    case "discard":return ["other","Discarded a dropped file"];
    case "tag":return ["change",(e.tagged?"Tagged ":"Cleared the tag on ")+k];
    case "move":return ["change","Moved "+k+" from "+nm(e.from)+" to "+nm(e.to)];
    case "env.create":return ["change","Created the set "+nm(e.name)];
    case "env.rename":return ["change","Renamed "+e.from+" to "+nm(e.to)];
    case "env.describe":return ["change","Edited the details of "+nm(e.name)];
    case "env.delete":case "rm.set":return ["change","Deleted the set "+(e.name||e.set||"")];
    case "env.order":return ["change","Changed the order sets apply in"];
    case "env.use":return ["change","Started using "+nm(e.name)+" here"];
    case "env.drop":return ["change","Stopped using "+nm(e.name)+" here"];
    case "team.add":return ["change","Gave "+(e.name||"someone")+" access"];
    case "team.remove":return ["change","Removed "+(e.name||"someone")];
    case "policy.update":return ["change","Changed what asks first"];
    case "setup":return ["change","Set up this folder"];
    case "global.create":return ["change","Created your library"];
    case "global.adopt":return ["change","Switched your library to "+(e.name||"")];
    case "verify":return ["other","Checked the vault"];
    case "rotate":return ["change","Rotated the vault key"];
    case "list":return ["other","Agent listed the secrets in "+(set||"a set")];
    case "describe":return ["other","Agent looked up "+(k||"a secret")];
    case "check":return ["other","Agent checked what the code needs"+(e.missing?" · "+e.missing+" missing":"")];
    case "provision":return ["other","Agent prepared "+(e.tool||e.service||"a tool")];
  }
  const parts=[];
  Object.keys(e).forEach(function(x){if(x==="at"||x==="actor"||x==="action")return;const v=e[x];if(v===undefined||v===null||v==="")return;parts.push(x+": "+list(v))});
  return ["other",(e.action||"event")+(parts.length?" — "+parts.join(", "):"")];
}
function relTime(iso){
  const t=new Date(iso).getTime();if(isNaN(t))return "";
  const s=Math.max(0,Math.round((Date.now()-t)/1000));
  if(s<60)return "just now";
  const m=Math.round(s/60);if(m<60)return m+" min ago";
  const hr=Math.round(m/60);if(hr<24)return hr+" h ago";
  return new Date(t).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
}
function dayLabel(iso){
  const d=new Date(iso);if(isNaN(d.getTime()))return "Earlier";
  const today=new Date();today.setHours(0,0,0,0);
  const that=new Date(d);that.setHours(0,0,0,0);
  const diff=Math.round((today-that)/86400000);
  return diff===0?"Today":diff===1?"Yesterday":d.toLocaleDateString([],{weekday:"long",month:"short",day:"numeric"});
}
let AUDIT=null;
let auditLoading=false;
async function loadAudit(){
  if(auditLoading)return;auditLoading=true;
  try{AUDIT=(await api("/api/audit",{})).entries||[]}catch(e){AUDIT=[]}
  finally{auditLoading=false}
  if(route()==="activity")render();
}
function renderActivity(page){
  page.append(h("header",{class:"head"},h("div",null,h("h1",null,"Activity"),
    h("p",{text:"What was done with this project's secrets, by you, your terminal and your agent. Values are never logged."})),
    h("div",{class:"actions"},h("button",{type:"button",class:"btn",onclick:function(){AUDIT=null;render();loadAudit()}},"Refresh"))));
  if(AUDIT===null){page.append(h("p",{class:"muted",text:"Loading…"}));loadAudit();return}
  if(!AUDIT.length){page.append(h("div",{class:"card"},h("div",{class:"empty"},h("h3",null,"Nothing yet"),h("p",null,"Runs, reveals and changes show up here."))));return}
  let day=null,box=null;
  AUDIT.forEach(function(e){
    const dl=dayLabel(e.at);
    if(dl!==day){day=dl;page.append(h("div",{class:"day",text:dl}));box=h("div",{class:"card"});page.append(box)}
    const d=describeEvent(e);
    box.append(h("div",{class:"ev"},h("span",{class:"kind "+d[0]}),
      h("div",null,h("span",{text:d[1]}),h("span",{class:"who",text:WHO[e.actor]||e.actor||""})),
      h("time",{datetime:e.at,title:new Date(e.at).toLocaleString(),text:relTime(e.at)})));
  });
}

/* ------------------------------------------------------ import a .env -- */

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
  page.append(h("div",{class:"card"},h("div",{class:"empty"},h("h3",null,"Couldn't load"),h("p",{text:e.message}))));
});
</script></body></html>`;
