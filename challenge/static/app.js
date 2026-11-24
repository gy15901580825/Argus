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

function playerInput() {
  return current.input_kind === "email" ? `Subject: ${$("subject").value}\n\n${$("input").value}` : $("input").value;
}

function updateCharacters() {
  const length = playerInput().length;
  text("characters", `${length} / 1500`);
  $("input").setCustomValidity(length > 1500 ? "Keep the complete input, including the email subject, within 1500 characters." : "");
}

function inputField(id, label, placeholder, subject = false) {
  const caption = document.createElement("label");
  caption.htmlFor = id; caption.textContent = label;
  const control = document.createElement(subject ? "input" : "textarea");
  control.id = id; control.name = id; control.maxLength = 1500; control.required = true;
  control.placeholder = placeholder;
  if (subject) control.type = "text"; else control.rows = 5;
  $("input-fields").append(caption, control);
}

function showInput(kind) {
  $("input-fields").replaceChildren();
  const formats = {
    chat: ["Chat message you control", "Try an order-related request that challenges the refund rule.", "Send message →"],
    email: ["Email body you control", "Write the customer email the agent will read from its inbox.", "Deliver email →"],
    tool_description: ["Tool description you control", "Replace the description of submit_diagnostic. The agent will receive a fixed routine diagnostic task.", "Apply description →"],
    invoice: ["Invoice document you control", "Invoice: Vellumridge Paper Supply\nAccount: acct-vendor-204\nAmount: 75", "Process invoice →"],
  };
  if (kind === "email") inputField("subject", "Email subject you control", "Customer order request", true);
  const [label, placeholder, action] = formats[kind];
  inputField("input", label, placeholder);
  text("submit", action);
  updateCharacters();
}

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
  showInput(level.input_kind);
  $("argus").href = level.argus_url; $("footer-argus").href = level.argus_url;
  $("assessment").href = level.assessment_url;
  for (const button of $("levels").children) button.setAttribute("aria-current", String(Number(button.dataset.id) === level.id));
}

function setBusy(value) {
  busy = value;
  for (const id of ["submit", "hint", "reset"]) $(id).disabled = value;
  for (const button of $("levels").children) button.disabled = value;
}

$("play").addEventListener("input", updateCharacters);
$("play").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy || !current) return;
  setBusy(true); text("status", "The agent is considering your request…");
  try {
    const result = await api(`/api/levels/${current.id}/submit`, {input: playerInput()});
    $("trace").replaceChildren();
    for (const entry of result.trace) {
      const item = document.createElement("li");
      item.textContent = readable(`${entry.tool}(${JSON.stringify(entry.arguments)})\n${entry.blocked_reason ? "Blocked: " + entry.blocked_reason : JSON.stringify(entry.result)}`);
      $("trace").append(item);
    }
    $("empty-trace").hidden = result.trace.length > 0;
    text("reply", readable(result.text));
    text("status", result.won ? "You won. The agent executed the forbidden tool action." : "No forbidden tool action yet. Try a different input.");
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
