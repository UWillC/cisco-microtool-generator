const API_BASE_URL = "http://127.0.0.1:8000"; // or http://localhost:8000

// Tab switching
const tabButtons = document.querySelectorAll(".tab-button");
const tabContents = document.querySelectorAll(".tab-content");

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;

    tabButtons.forEach((b) => b.classList.remove("active"));
    tabContents.forEach((c) => c.classList.remove("active"));

    btn.classList.add("active");
    document.getElementById(`tab-${tab}`).classList.add("active");
  });
});

// Helper: copy output to clipboard
document.querySelectorAll(".btn-secondary[data-copy-target]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const targetId = btn.dataset.copyTarget;
    const textarea = document.getElementById(targetId);
    if (!textarea) return;

    textarea.select();
    textarea.setSelectionRange(0, 99999);
    document.execCommand("copy");

    const original = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => {
      btn.textContent = original;
    }, 1200);
  });
});

// Helper: generic POST
async function postJSON(path, payload) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(
      `Request failed (${res.status}): ${text || res.statusText}`
    );
  }

  return res.json();
}

// SNMPv3 form
const snmpForm = document.getElementById("snmpv3-form");
const snmpOutput = document.getElementById("snmpv3-output");

snmpForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  snmpOutput.value = "Generating SNMPv3 config...";

  const formData = new FormData(snmpForm);
  const payload = {
    mode: formData.get("mode"),
    device: formData.get("device"),
    host: formData.get("host"),
    user: formData.get("user"),
    group: formData.get("group"),
    auth_password: formData.get("auth_password"),
    priv_password: formData.get("priv_password"),
    output_format: formData.get("output_format"),
  };

  try {
    const data = await postJSON("/generate/snmpv3", payload);
    snmpOutput.value = data.config || "";
  } catch (err) {
    snmpOutput.value = `Error: ${err.message}`;
  }
});

// NTP form
const ntpForm = document.getElementById("ntp-form");
const ntpOutput = document.getElementById("ntp-output");

ntpForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  ntpOutput.value = "Generating NTP config...";

  const formData = new FormData(ntpForm);
  const useAuth = formData.get("use_auth") === "true";

  const payload = {
    device: formData.get("device"),
    primary_server: formData.get("primary_server"),
    secondary_server: formData.get("secondary_server") || null,
    timezone: formData.get("timezone"),
    use_auth: useAuth,
    key_id: useAuth ? formData.get("key_id") || null : null,
    key_value: useAuth ? formData.get("key_value") || null : null,
    output_format: formData.get("output_format"),
  };

  try {
    const data = await postJSON("/generate/ntp", payload);
    ntpOutput.value = data.config || "";
  } catch (err) {
    ntpOutput.value = `Error: ${err.message}`;
  }
});

// AAA form
const aaaForm = document.getElementById("aaa-form");
const aaaOutput = document.getElementById("aaa-output");

aaaForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  aaaOutput.value = "Generating AAA config...";

  const formData = new FormData(aaaForm);

  const payload = {
    device: formData.get("device"),
    mode: formData.get("mode") === "local-only" ? "local-only" : "tacacs",
    enable_secret: formData.get("enable_secret") || null,
    tacacs1_name: formData.get("tacacs1_name") || null,
    tacacs1_ip: formData.get("tacacs1_ip") || null,
    tacacs1_key: formData.get("tacacs1_key") || null,
    tacacs2_name: formData.get("tacacs2_name") || null,
    tacacs2_ip: formData.get("tacacs2_ip") || null,
    tacacs2_key: formData.get("tacacs2_key") || null,
    source_interface: formData.get("source_interface") || null,
    output_format: formData.get("output_format"),
  };

  try {
    const data = await postJSON("/generate/aaa", payload);
    aaaOutput.value = data.config || "";
  } catch (err) {
    aaaOutput.value = `Error: ${err.message}`;
  }
});

// Golden config form
const goldenForm = document.getElementById("golden-form");
const goldenOutput = document.getElementById("golden-output");

goldenForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  goldenOutput.value = "Generating Golden Config...";

  const formData = new FormData(goldenForm);

  const payload = {
    device: formData.get("device"),
    mode: formData.get("mode"),
    snmpv3_config: formData.get("snmpv3_config") || null,
    ntp_config: formData.get("ntp_config") || null,
    aaa_config: formData.get("aaa_config") || null,
    output_format: formData.get("output_format"),
  };

  try {
    const data = await postJSON("/generate/golden-config", payload);
    goldenOutput.value = data.config || "";
  } catch (err) {
    goldenOutput.value = `Error: ${err.message}`;
  }
});
