"use strict";
const $ = (id) => document.getElementById(id);
let levels = [];
let current = null;
let busy = false;

function readable(value) {
  return String(value).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, "&");
}

async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.detail || "The request could not be completed.");
  return result;
}

function text(id, value) { $(id).textContent = value; }

function clearTurn() {
  $("trace").replaceChildren();
  text("reply", ""); text("status", ""); text("hint-text", "");
  text("hint", "Hint (0/3)");
  $("empty-trace").hidden = false;
  $("hint-text").hidden = true;
  $("win").hidden = true;
  $("consent").checked = false; $("consent").disabled = false; $("share").disabled = true;
  text("share-status", "");
}

function choose(level) {
  current = level;
  clearTurn();
  text("level-number", `LEVEL ${level.id} / ${levels.length}`);
  text("level-title", level.title); text("goal", level.goal);
  $("dev").hidden = !level.dev_mode;
  $("input").value = ""; text("characters", "0 / 1500");
  $("argus").href = level.argus_url; $("footer-argus").href = level.argus_url;
  $("assessment").href = level.assessment_url;
  for (const button of $("levels").children) button.setAttribute("aria-current", String(Number(button.dataset.id) === level.id));
}

function setBusy(value) {
  busy = value;
  for (const id of ["submit", "hint", "reset"]) $(id).disabled = value;
  for (const button of $("levels").children) button.disabled = value;
}

$("input").addEventListener("input", () => text("characters", `${$("input").value.length} / 1500`));
$("play").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy || !current) return;
  setBusy(true); text("status", "The agent is considering your request…");
  try {
    const result = await api(`/api/levels/${current.id}/submit`, {input: $("input").value});
    $("trace").replaceChildren();
    for (const entry of result.trace) {
      const item = document.createElement("li");
      item.textContent = readable(`${entry.tool}(${JSON.stringify(entry.arguments)})\n${entry.blocked_reason ? "Blocked: " + entry.blocked_reason : JSON.stringify(entry.result)}`);
      $("trace").append(item);
    }
    $("empty-trace").hidden = result.trace.length > 0;
    text("reply", readable(result.text));
    text("status", result.won ? "You won. The agent executed a refund above the limit." : "No forbidden tool action yet. Try a different request.");
    if (result.won) {
      $("win").hidden = false;
      text("explainer", current.explainer);
      text("mappings", `OWASP categories: ${current.owasp.join(", ")}`);
      $("probes").replaceChildren();
      for (const probe of current.probe_ids) { const item = document.createElement("li"); item.textContent = probe; $("probes").append(item); }
    }
  } catch (error) { text("status", error.message); }
  finally { setBusy(false); }
});

$("hint").addEventListener("click", async () => {
  if (busy || !current) return;
  setBusy(true);
  try { const result = await api(`/api/levels/${current.id}/hint`); text("hint-text", result.hint); $("hint-text").hidden = false; text("hint", `Hint (${result.used}/3)`); }
  catch (error) { text("status", error.message); }
  finally { setBusy(false); }
});

$("reset").addEventListener("click", async () => {
  if (busy || !current) return;
  setBusy(true);
  try { await api(`/api/levels/${current.id}/reset`, {}); clearTurn(); text("status", "World reset. Submission limits still apply."); }
  catch (error) { text("status", error.message); }
  finally { setBusy(false); }
});

$("consent").addEventListener("change", () => { $("share").disabled = !$("consent").checked; });
$("share").addEventListener("click", async () => {
  if (!current || !$("consent").checked) return;
  setBusy(true);
  $("share").disabled = true;
  try { await api(`/api/levels/${current.id}/share`, {consent: true}); text("share-status", "Winning attack shared. Thank you."); $("consent").disabled = true; }
  catch (error) { text("share-status", error.message); $("share").disabled = false; }
  finally { setBusy(false); }
});

api("/api/levels").then((catalog) => {
  levels = catalog;
  for (const level of levels) {
    const button = document.createElement("button");
    button.type = "button"; button.className = "secondary"; button.dataset.id = level.id;
    button.textContent = `Level ${level.id} · ${level.title}`;
    button.addEventListener("click", () => { if (!busy) choose(level); });
    $("levels").append(button);
  }
  choose(levels[0]);
}).catch((error) => text("status", error.message));
