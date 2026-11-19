"""FastAPI regression console.

One page, two independent rounds (轮次 A / 轮次 B).  Each round lets the
operator

  * compose a regression case of up to 12 steps -- switch the authoritative
    endpoint (A address and delay, NXDOMAIN, or no answer), wait, and query
    ``service.example`` A through that round's resolver; waits add up to at
    most 30s per case;
  * fill each query step's expectations -- RCODE, A address and authoritative
    setting step number, the latter two optionally "none" -- and see the real
    UDP reply compared step by step;
  * keep using the round's live endpoints while a case runs: ad-hoc queries
    and manual authoritative mode switches go to that round's own processes,
    and the round's own cache and logs are shown.

Rounds are isolated: their own authoritative endpoint, resolver, SQLite
database, cache and logs, each starting from an empty cache, so both may run
at the same time.  A round whose endpoint fails to start, or a query that
receives no DNS reply at all, is marked interrupted at that point with the
cause; results already measured are kept and the round's resources are
recycled at the end (or on interruption) via ``app.rounds``.
"""
from __future__ import annotations

import ipaddress
import time

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import common, regression, rounds

app = FastAPI(title="DNS 回归控制台")

PAGE = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>DNS 回归控制台</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 1.6rem; background:#f5f6f8; color:#1d2330; }
  h1 { font-size:1.25rem; margin-bottom:.2rem; }
  .sub { color:#667; font-size:.85rem; margin-bottom:1rem; }
  .rounds { display:grid; grid-template-columns:1fr 1fr; gap:1rem; }
  @media (max-width: 1100px) { .rounds { grid-template-columns:1fr; } }
  section.round { background:#fff; border:1px solid #d9dde5; border-radius:10px;
                  padding:1rem 1.1rem; }
  section.round h2 { font-size:1.05rem; margin:0 0 .2rem; }
  .state { font-size:.8rem; color:#667; margin-bottom:.6rem; }
  h3 { font-size:.9rem; margin:1rem 0 .4rem; border-top:1px solid #eceef2; padding-top:.7rem; }
  table { border-collapse:collapse; width:100%; font-size:.8rem; }
  th, td { border:1px solid #e3e6ec; padding:.22rem .4rem; text-align:left; vertical-align:top; }
  th { background:#f2f4f8; font-weight:600; }
  input[type=text] { width:8.5rem; } input[type=number] { width:4.6rem; }
  select { max-width:9.5rem; }
  button { padding:.3rem .8rem; cursor:pointer; border:1px solid #b9c0cc;
           background:#fff; border-radius:5px; }
  button.primary { background:#2f6fde; border-color:#2f6fde; color:#fff; }
  button:disabled { opacity:.5; cursor:not-allowed; }
  .pill { display:inline-block; padding:.05rem .45rem; border-radius:1rem;
          background:#e8ecf3; font-size:.75rem; margin-right:.3rem; }
  .ok { color:#0a7a2f; } .bad { color:#b00020; } .muted { color:#777; }
  tr.ok td { background:#f2fbf5; } tr.fail td { background:#fdf1f2; }
  tr.interrupted td { background:#fff6e8; } tr.skipped td { color:#99a; }
  pre { background:#0d1420; color:#cfe3ff; padding:.55rem; border-radius:6px;
        overflow:auto; font-size:.72rem; max-height:11rem; }
  .notice { padding:.5rem .7rem; border-radius:6px; margin:.5rem 0; font-size:.83rem; }
  .notice.bad { background:#fdecee; border:1px solid #f3b9c0; }
  .row { margin:.3rem 0; }
  .steps td { padding:.2rem .35rem; }
  .steps input[type=text] { width:6.6rem; } .steps input[type=number] { width:4rem; }
  .steps select { max-width:7rem; }
</style>
</head>
<body>
<h1>DNS 回归控制台 — service.example A</h1>
<div class="sub" id="params"></div>
<div class="rounds" id="rounds"></div>

<script>
const MAX_STEPS = 12, MAX_WAIT = 30;
const ROUND_IDS = ['A', 'B'];
const MODES = [['a','A 记录'],['nxdomain','NXDOMAIN'],['delay','延迟应答'],['timeout','超时（不应答）']];
const RCODES = ['NOERROR','NXDOMAIN','SERVFAIL','REFUSED','NODATA'];

// Per-round browser state: the composed case plus the latest live snapshot.
const ui = {};
for (const id of ROUND_IDS) ui[id] = {steps: [], live: null};
const editing = new Set();   // round ids whose editor must not be rebuilt

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  Object.assign(node, props || {});
  for (const c of children) if (c !== null && c !== undefined) node.append(c);
  return node;
}
function opt(value, label, selected) {
  const o = el('option', {value}); o.textContent = label;
  if (selected) o.selected = true;
  return o;
}
function fmtTs(ts) { return ts ? new Date(ts * 1000).toLocaleTimeString() : ''; }

function newModeStep() { return {type:'mode', mode:'a', ip:'192.0.2.10', delay_seconds:3}; }
function newWaitStep() { return {type:'wait', seconds:5}; }
function newQueryStep() { return {type:'query', expect_rcode:'NOERROR', expect_ip:'', expect_step:''}; }

// Ready-to-run cases.  The preset uses this round's own A address.
function presets(ip) {
  ip = ip || '192.0.2.10';
  return [
    {name:'基本：回源 / 命中新鲜缓存', build: () => [
      {type:'mode', mode:'a', ip, delay_seconds:3},
      {type:'query', expect_rcode:'NOERROR', expect_ip:ip, expect_step:'1'},
      {type:'query', expect_rcode:'NOERROR', expect_ip:ip, expect_step:'1'},
    ]},
    {name:'相同 A 地址：用设置步骤号区分', build: () => [
      {type:'mode', mode:'a', ip, delay_seconds:3},
      {type:'query', expect_rcode:'NOERROR', expect_ip:ip, expect_step:'1'},
      {type:'wait', seconds:6},
      {type:'mode', mode:'a', ip, delay_seconds:1},
      {type:'query', expect_rcode:'NOERROR', expect_ip:ip, expect_step:'4'},
    ]},
    {name:'过期 + 权威失联：沿用旧 A', build: () => [
      {type:'mode', mode:'a', ip, delay_seconds:3},
      {type:'query', expect_rcode:'NOERROR', expect_ip:ip, expect_step:'1'},
      {type:'mode', mode:'timeout', ip, delay_seconds:3},
      {type:'wait', seconds:6},
      {type:'query', expect_rcode:'NOERROR', expect_ip:ip, expect_step:'1'},
    ]},
    {name:'NXDOMAIN 清除旧 A', build: () => [
      {type:'mode', mode:'a', ip, delay_seconds:3},
      {type:'query', expect_rcode:'NOERROR', expect_ip:ip, expect_step:'1'},
      {type:'mode', mode:'nxdomain', ip, delay_seconds:3},
      {type:'wait', seconds:6},
      {type:'query', expect_rcode:'NXDOMAIN', expect_ip:'', expect_step:'3'},
    ]},
  ];
}

function totalWait(steps) {
  return steps.reduce((s, x) => s + (x.type === 'wait' ? Number(x.seconds) || 0 : 0), 0);
}

// ---- rendering -----------------------------------------------------------
function render(id) {
  const box = document.getElementById('round' + id);
  const live = ui[id].live || {};
  const r = live.round || {};
  box.innerHTML = '';

  box.append(el('h2', {}, '轮次 ' + id));
  const pills = [];
  if (r.auth_port) pills.push(el('span', {className:'pill'}, '权威 udp/' + r.auth_port));
  if (r.resolver_port) pills.push(el('span', {className:'pill'}, '解析器 udp/' + r.resolver_port));
  pills.push(el('span', {className:'pill'},
    live.active ? '端点运行中' : (r.finished ? '已结束' : '空闲')));
  if (live.control) pills.push(el('span', {className:'pill'},
    '权威：' + live.control.mode + ' A=' + live.control.ip +
    ' 延迟=' + live.control.delay_seconds + 's'));
  box.append(el('div', {className:'state'}, ...pills));

  if (live.failure) {
    box.append(el('div', {className:'notice bad'},
      '已中断：' + live.failure.message +
      (live.failure.hint ? '（' + live.failure.hint + '）' : '')));
  }

  box.append(el('h3', {}, '回归用例（最多 ' + MAX_STEPS + ' 步，合计等待 ≤ ' + MAX_WAIT + 's）'));

  const steps = ui[id].steps;
  if (!editing.has(id)) {
    // Not editing: show a read-only summary of the case.
    if (!steps.length) {
      box.append(el('div', {className:'row muted'}, '尚未编排用例。选择预置用例或添加步骤。'));
    } else {
      const table = el('table');
      table.append(el('thead', {}, el('tr', {},
        el('th', {}, '#'), el('th', {}, '类型'), el('th', {}, '内容'))));
      const body = el('tbody');
      steps.forEach((s, i) => body.append(el('tr', {},
        el('td', {}, String(i + 1)), el('td', {}, stepName(s)),
        el('td', {}, stepSummary(s)))));
      table.append(body);
      box.append(table);
    }
  } else {
    box.append(editor(id, steps));
  }

  const wait = totalWait(steps);
  const controls = el('div', {className:'row'});
  controls.append(el('span', {className: wait > MAX_WAIT ? 'bad' : 'muted'},
    '合计等待 ' + wait + 's / ' + MAX_WAIT + 's  '));
  const running = !!(live.regression && live.regression.status === 'running');
  const editBtn = el('button', {}, editing.has(id) ? '完成编排' : '编排用例');
  editBtn.disabled = running;
  editBtn.onclick = () => {
    if (editing.has(id)) editing.delete(id); else editing.add(id);
    render(id);
  };
  const startBtn = el('button', {}, live.active ? '轮次已启动' : '启动轮次');
  startBtn.disabled = !!live.active || running;
  startBtn.onclick = () => startRound(id);
  const run = el('button', {className:'primary'}, '运行用例');
  run.disabled = steps.length === 0 || running;
  run.onclick = () => runCase(id);
  const stop = el('button', {}, '结束并回收');
  stop.disabled = !live.active && !running;
  stop.onclick = () => stopRound(id);
  controls.append(editBtn, ' ', startBtn, ' ', run, ' ', stop);
  box.append(controls);

  const reg = live.regression;
  if (reg) box.append(el('h3', {}, '逐条对照'), resultsTable(reg));

  box.append(el('h3', {}, '现场操作（使用本轮权威端与解析器，未填设置步骤）'));
  box.append(liveControls(id, live));

  box.append(el('h3', {}, '本轮缓存'), cacheLine(live.cache));
  box.append(el('h3', {}, '解析器查询日志'),
    logTable(live.resolver_log, ['ts','qname','qtype','source','rcode','answers','detail']));
  box.append(el('h3', {}, '权威端接收日志'),
    logTable(live.auth_log, ['ts','qname','qtype','mode','action','detail']));
  box.append(el('h3', {}, '轮次日志'), el('pre', {}, (live.logs || []).join('\\n')));
}

function stepName(s) {
  return s.type === 'mode' ? '权威设置' : s.type === 'wait' ? '等待' : '查询';
}
function stepSummary(s) {
  if (s.type === 'mode') {
    return MODES.find(m => m[0] === s.mode)[1] + ' · A=' + (s.ip || '沿用') +
      ' · 延迟=' + (Number(s.delay_seconds) || 0) + 's';
  }
  if (s.type === 'wait') return '等待 ' + (Number(s.seconds) || 0) + 's';
  return '预期 RCODE=' + s.expect_rcode + ' · A=' + (s.expect_ip || '无') +
    ' · 设置步骤=' + (s.expect_step === '' || s.expect_step === null ? '无' : s.expect_step);
}

function editor(id, steps) {
  const wrap = el('div');
  const preset = el('select');
  preset.append(opt('', '预置用例…', true));
  presets((ui[id].live && ui[id].live.control || {}).ip).forEach((p, i) =>
    preset.append(opt(String(i), p.name)));
  preset.onchange = () => {
    if (preset.value === '') return;
    const p = presets((ui[id].live && ui[id].live.control || {}).ip)[Number(preset.value)];
    ui[id].steps = p.build();
    render(id);
  };
  const add = (label, factory) => {
    const b = el('button', {}, label);
    b.onclick = () => {
      if (ui[id].steps.length >= MAX_STEPS) { alert('最多 ' + MAX_STEPS + ' 步'); return; }
      ui[id].steps.push(factory()); render(id);
    };
    return b;
  };
  const clear = el('button', {}, '清空');
  clear.onclick = () => { ui[id].steps = []; render(id); };
  wrap.append(el('div', {className:'row'}, preset, ' ',
    add('+ 权威设置', newModeStep), ' ', add('+ 等待', newWaitStep), ' ',
    add('+ 查询', newQueryStep), ' ', clear));

  const table = el('table', {className:'steps'});
  table.append(el('thead', {}, el('tr', {},
    el('th', {}, '#'), el('th', {}, '类型'), el('th', {}, '参数'),
    el('th', {}, '预期（查询步骤）'), el('th', {}, ''))));
  const body = el('tbody');
  steps.forEach((step, idx) => body.append(editorRow(id, step, idx)));
  table.append(body);
  wrap.append(table);
  return wrap;
}

function editorRow(id, step, idx) {
  const steps = ui[id].steps;
  const tr = el('tr');
  tr.append(el('td', {}, String(idx + 1)));
  const kind = el('select');
  kind.append(opt('mode', '权威设置', step.type === 'mode'));
  kind.append(opt('wait', '等待', step.type === 'wait'));
  kind.append(opt('query', '查询', step.type === 'query'));
  kind.onchange = () => {
    steps[idx] = kind.value === 'mode' ? newModeStep()
      : kind.value === 'wait' ? newWaitStep() : newQueryStep();
    render(id);
  };
  tr.append(el('td', {}, kind));

  if (step.type === 'mode') {
    const mode = el('select');
    MODES.forEach(([v, label]) => mode.append(opt(v, label, step.mode === v)));
    mode.onchange = () => { step.mode = mode.value; };
    const ip = el('input', {type:'text', value: step.ip || '', placeholder:'沿用'});
    ip.onchange = () => { step.ip = ip.value.trim(); };
    const delay = el('input', {type:'number', min:'0', max:'60', step:'0.5',
                               value: step.delay_seconds});
    delay.onchange = () => { step.delay_seconds = Number(delay.value) || 0; };
    tr.append(el('td', {}, mode, ' A：', ip, ' 延迟：', delay, 's'),
      el('td', {className:'muted'}, '应答会带回设置步骤号 ' + (idx + 1)));
  } else if (step.type === 'wait') {
    const seconds = el('input', {type:'number', min:'0', step:'0.5', value: step.seconds});
    seconds.onchange = () => { step.seconds = Number(seconds.value) || 0; render(id); };
    tr.append(el('td', {}, '等待 ', seconds, 's'), el('td', {className:'muted'}, ''));
  } else {
    const rcode = el('select');
    RCODES.forEach(v => rcode.append(opt(v, v, step.expect_rcode === v)));
    rcode.onchange = () => { step.expect_rcode = rcode.value; };
    const ip = el('input', {type:'text', value: step.expect_ip || '',
                            placeholder:'无', title:'预期 A 地址，留空表示无'});
    ip.onchange = () => { step.expect_ip = ip.value.trim(); };
    const stepNo = el('input', {type:'text',
      value: step.expect_step === null || step.expect_step === undefined ? '' : String(step.expect_step),
      placeholder:'无', title:'预期权威设置步骤号，留空表示无'});
    stepNo.onchange = () => { step.expect_step = stepNo.value.trim(); };
    tr.append(el('td', {}, 'RCODE：', rcode, ' A：', ip, ' 设置步骤：', stepNo),
      el('td', {className:'muted'}, '真实 UDP 查询后逐项比对'));
  }
  const del = el('button', {}, '删除');
  del.onclick = () => { steps.splice(idx, 1); render(id); };
  tr.append(el('td', {}, del));
  return tr;
}

function resultsTable(reg) {
  const wrap = el('div', {});
  const count = {ok: 0, fail: 0, skipped: 0, interrupted: 0};
  reg.results.forEach(r => { count[r.status] = (count[r.status] || 0) + 1; });
  wrap.append(el('div', {className:'row'},
    el('span', {className:'pill'},
      '状态：' + (reg.status === 'running' ? '运行中…' : reg.status === 'done' ? '完成' : '中断')),
    el('span', {className:'pill ok'}, '通过 ' + count.ok),
    el('span', {className:'pill bad'}, '失败 ' + count.fail),
    el('span', {className:'pill'}, '未执行 ' + count.skipped),
    el('span', {className:'pill'}, '中断 ' + count.interrupted)));
  const table = el('table');
  table.append(el('thead', {}, el('tr', {},
    el('th', {}, '#'), el('th', {}, '步骤内容'), el('th', {}, '结果'),
    el('th', {}, '说明 / 真实答复'))));
  const body = el('tbody');
  reg.results.forEach(r => {
    const a = r.actual || {};
    const actual = a.rcode ? el('div', {className:'muted'},
      '实际：' + a.rcode + ' · A=' + ((a.a_records && a.a_records.length) ? a.a_records.join(',') : '无') +
      ' · 来源=' + (a.source || '—') + ' · 设置步骤=' + (a.auth_step || '无') +
      ' · ' + a.elapsed_ms + 'ms') : null;
    body.append(el('tr', {className: r.status},
      el('td', {}, r.step_no === null ? '启动' : String(r.step_no)),
      el('td', {}, r.description),
      el('td', {},
        r.status === 'ok' ? '通过' : r.status === 'fail' ? '失败'
          : r.status === 'skipped' ? '未执行' : '中断'),
      el('td', {}, r.detail, actual)));
  });
  table.append(body);
  wrap.append(table);
  return wrap;
}

function liveControls(id, live) {
  const wrap = el('div');
  const ctl = live.control || {};
  const mode = el('select');
  MODES.forEach(([v, label]) => mode.append(opt(v, label, ctl.mode === v)));
  const ip = el('input', {type:'text', value: ctl.ip || '192.0.2.10'});
  const delay = el('input', {type:'number', min:'0', step:'0.5',
                             value: ctl.delay_seconds === undefined ? 3 : ctl.delay_seconds});
  const apply = el('button', {}, '应用设置');
  const msg = el('span', {className:'muted'});
  apply.onclick = async () => {
    const r = await post('/api/rounds/' + id + '/mode',
      {mode: mode.value, ip: ip.value.trim(), delay_seconds: Number(delay.value)});
    msg.textContent = r.ok ? ' 已切换（设置步骤留空）' : ' 错误：' + r.error;
    refresh();
  };
  wrap.append(el('div', {className:'row'}, mode, ' A：', ip, ' 延迟：', delay, 's ',
    apply, msg));
  const qbtn = el('button', {className:'primary'}, '现场查询 A 记录');
  const out = el('div', {className:'row'});
  qbtn.onclick = async () => {
    out.textContent = '查询中…';
    const r = await post('/api/rounds/' + id + '/query', {});
    if (!r.ok) {
      out.innerHTML = '<b class="bad">查询失败：' + (r.reason || r.error || '') + '</b>';
      refresh(); return;
    }
    const ans = r.answers.length
      ? r.answers.map(a => a.type + ' ' + a.data + ' TTL=' + a.ttl + 's').join('，')
      : '（无应答记录）';
    out.innerHTML = '<b>' + r.rcode + '</b> ' + ans +
      ' <span class="pill">来源 ' + r.source + '</span>' +
      ' <span class="pill">设置步骤 ' + (r.auth_step || '无') + '</span>' +
      ' <span class="muted">' + r.elapsed_ms + 'ms</span>';
    refresh();
  };
  wrap.append(el('div', {className:'row'}, qbtn), out);
  return wrap;
}

function cacheLine(cache) {
  if (!cache) return el('div', {className:'muted'}, '（缓存为空）');
  const now = Date.now() / 1000;
  return el('div', {},
    el('span', {className:'pill'}, 'rcode=' + cache.rcode),
    el('span', {className:'pill'}, cache.a_record ? 'A=' + cache.a_record : '无 A 记录'),
    el('span', {className:'pill'}, '设置步骤=' + (cache.auth_step || '无')),
    el('span', {className: cache.fresh_until > now ? 'pill ok' : 'pill bad'},
      cache.fresh_until > now ? '新鲜缓存有效' : '新鲜缓存已过期'),
    cache.stale_until ? el('span', {className:'pill'}, '有过期备用') : null);
}

function logTable(rows, cols) {
  const table = el('table');
  table.append(el('thead', {}, el('tr', {}, ...cols.map(c => el('th', {}, c)))));
  const body = el('tbody');
  (rows || []).forEach(r => body.append(el('tr', {}, ...cols.map(c =>
    el('td', {}, c === 'ts' ? fmtTs(r.ts) : (r[c] === null || r[c] === undefined ? '' : String(r[c])))))));
  table.append(body);
  return table;
}

// ---- api -----------------------------------------------------------------
async function post(url, body) {
  const resp = await fetch(url, {method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify(body || {})});
  try { return await resp.json(); }
  catch (e) { return {ok:false, error: resp.status + ' ' + resp.statusText}; }
}

async function runCase(id) {
  const r = await post('/api/rounds/' + id + '/run', {steps: ui[id].steps});
  if (!r.ok) alert('无法运行：' + r.error);
  refresh();
}
async function startRound(id) {
  const r = await post('/api/rounds/' + id + '/start', {});
  if (!r.ok) alert('无法启动：' + (r.error || r.reason || ''));
  refresh();
}
async function stopRound(id) { await post('/api/rounds/' + id + '/stop', {}); refresh(); }

function hasFocusInside(id) {
  const box = document.getElementById('round' + id);
  const active = document.activeElement;
  return !!(box && active && box.contains(active)
            && ['INPUT', 'SELECT', 'TEXTAREA'].includes(active.tagName));
}

async function refresh() {
  await Promise.all(ROUND_IDS.map(async id => {
    try { ui[id].live = await (await fetch('/api/rounds/' + id)).json(); }
    catch (e) { /* keep the previous snapshot */ }
  }));
  // Rebuilding while a field is being edited would wipe what is being typed;
  // the next poll after focus leaves catches up.
  for (const id of ROUND_IDS) if (!hasFocusInside(id)) render(id);
}

async function boot() {
  const p = await (await fetch('/api/params')).json();
  document.getElementById('params').textContent =
    '成功答复 TTL=' + p.fresh_ttl + 's · 过期后旧 A 最多沿用 ' + p.stale_window +
    's · 上游超时 ' + p.upstream_timeout + 's · 每轮独立权威端 / 解析器 / 缓存 / 日志';
  for (const id of ROUND_IDS)
    document.getElementById('rounds').append(el('section', {className:'round', id:'round' + id}));
  // Two sensible starting cases, one per round, so a run is one click away.
  ui.A.steps = presets()[1].build();
  ui.B.steps = presets()[2].build();
  await refresh();
  setInterval(refresh, 2000);
}
boot();
</script>
</body>
</html>
"""


class ModeIn(BaseModel):
    mode: str
    ip: str | None = None
    delay_seconds: float | None = None


class CaseIn(BaseModel):
    steps: list[dict]


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return PAGE


@app.get("/api/params")
def params() -> dict:
    return {
        "now": time.time(),
        "domain": common.FIXED_DOMAIN,
        "fresh_ttl": common.FRESH_TTL,
        "stale_window": common.STALE_WINDOW,
        "upstream_timeout": common.UPSTREAM_TIMEOUT,
        "max_steps": regression.MAX_STEPS,
        "max_total_wait": regression.MAX_TOTAL_WAIT,
    }


def _round_or_error(round_id: str):
    if round_id not in rounds.ROUND_IDS:
        return None, JSONResponse({"ok": False, "error": f"未知轮次 {round_id!r}"},
                                  status_code=404)
    rnd = rounds.get_round(round_id)
    if rnd is None or rnd.finished:
        return None, JSONResponse(
            {"ok": False, "error": "轮次未启动或已结束，请先运行用例"}, status_code=409)
    return rnd, None


@app.get("/api/rounds/{round_id}")
def round_state(round_id: str) -> JSONResponse:
    if round_id not in rounds.ROUND_IDS:
        return JSONResponse({"error": f"未知轮次 {round_id!r}"}, status_code=404)
    rnd = rounds.get_round(round_id)
    if rnd is None:
        return JSONResponse({"round": round_id, "started": False})
    state = rnd.as_dict()
    state["started"] = True
    state["control"] = common.get_control(rnd.db_path)
    return JSONResponse(state)


@app.post("/api/rounds/{round_id}/start")
def start_round(round_id: str) -> JSONResponse:
    """Start a round's endpoints without running a case, for live queries and
    manual mode switches.  The round still starts from an empty cache."""
    if round_id not in rounds.ROUND_IDS:
        return JSONResponse({"ok": False, "error": f"未知轮次 {round_id!r}"},
                            status_code=404)
    rnd = rounds.get_round(round_id)
    if rnd is not None and not rnd.finished and rnd.procs:
        return {"ok": True, "round": rnd.as_dict(), "already": True}
    rnd = rounds.start_round(round_id)
    payload = {"ok": rnd.failure is None, "round": rnd.as_dict()}
    if rnd.failure:
        payload["error"] = rnd.failure["reason"]
    return JSONResponse(payload, status_code=200 if payload["ok"] else 500)


@app.post("/api/rounds/{round_id}/run")
def run_round_case(round_id: str, case: CaseIn) -> JSONResponse:
    if round_id not in rounds.ROUND_IDS:
        return JSONResponse({"ok": False, "error": f"未知轮次 {round_id!r}"},
                            status_code=404)
    try:
        steps = regression.validate_case(case.steps)
    except regression.StepError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    rnd = rounds.start_round(round_id)
    try:
        rnd.run_case(steps)
    except RuntimeError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=409)
    return {"ok": True, "round": rnd.as_dict()}


@app.post("/api/rounds/{round_id}/mode")
def round_mode(round_id: str, m: ModeIn) -> JSONResponse:
    if m.mode not in regression.VALID_MODES:
        return JSONResponse({"ok": False, "error": f"unknown mode {m.mode!r}"}, 400)
    rnd, err = _round_or_error(round_id)
    if err:
        return err
    cur = common.get_control(rnd.db_path) or {"ip": common.DEFAULT_IP,
                                             "delay_seconds": common.DEFAULT_DELAY}
    ip = m.ip if m.ip is not None else cur["ip"]
    delay = m.delay_seconds if m.delay_seconds is not None else cur["delay_seconds"]
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return JSONResponse({"ok": False, "error": f"bad IPv4 address {ip!r}"}, 400)
    if not (0 <= float(delay) <= 60):
        return JSONResponse({"ok": False, "error": "delay must be 0..60s"}, 400)
    # Manual switch: no regression step number, so answers report an empty one.
    rnd.set_control(m.mode, ip, float(delay), step_no=None)
    return {"ok": True, "control": common.get_control(rnd.db_path)}


@app.post("/api/rounds/{round_id}/query")
def round_query(round_id: str) -> JSONResponse:
    rnd, err = _round_or_error(round_id)
    if err:
        return err
    failure = rnd.check_running()
    if failure:
        return JSONResponse({"ok": False, "error": failure["kind"],
                             "reason": failure["reason"]}, status_code=409)
    result = rnd.query()
    payload = {"ok": result.error is None, **result.as_dict()}
    if result.error:
        payload["reason"] = ("未收到 DNS 报文" if result.error == rounds.ERR_NO_REPLY
                             else result.error)
    return JSONResponse(payload)


@app.post("/api/rounds/{round_id}/stop")
def stop_round(round_id: str) -> JSONResponse:
    if round_id not in rounds.ROUND_IDS:
        return JSONResponse({"ok": False, "error": f"未知轮次 {round_id!r}"}, 404)
    rnd = rounds.get_round(round_id)
    if rnd is None:
        return {"ok": True, "state": None}
    rnd.finish()
    return {"ok": True, "state": rnd.as_dict()}


def main() -> None:
    common.init_db()
    uvicorn.run(app, host="0.0.0.0", port=common.WEB_PORT, log_level="warning")


if __name__ == "__main__":
    main()
