/**
 * The page's head and styles: tokens for light and dark, the shell, cards, lists, dialogs, and the phone layout.
 *
 * Part of the page `hush ui` serves; ui-page.ts joins the parts. A String.raw
 * template like the rest: no backticks and no dollar-brace inside.
 */
export const STYLES = String.raw`<!doctype html>
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
`;
