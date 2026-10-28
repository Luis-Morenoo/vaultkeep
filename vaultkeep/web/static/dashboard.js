// Dashboard: list, add and delete entries. Every request carries the JWT plus the
// master password, because the token proves login but can't decrypt the vault.
const token = localStorage.getItem("token");
if (!token) {
    window.location.href = "/";
}

const errorBox = document.getElementById("error-message");
const masterPassword = () => document.getElementById("master-password").value;

function showError(message) {
    errorBox.textContent = message || "";
}

function logout() {
    localStorage.removeItem("token");
    window.location.href = "/";
}

// Shared request helper: attaches the JWT, sends JSON,
// and sends the user back to login if the token has expired.
async function api(url, method, body) {
    const response = await fetch(url, {
        method: method,
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token
        },
        body: JSON.stringify(body)
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401 && data.error === "Unauthorized") {
        logout(); // JWT expired, invalid, or issued for another vault
    }
    return { ok: response.ok, data: data };
}

async function loadEntries() {
    if (!masterPassword()) {
        showError("Enter your master password first.");
        return;
    }
    const { ok, data } = await api("/vault/entries/list", "POST", { password: masterPassword() });
    if (!ok) {
        showError(data.error);
        return;
    }
    showError("");

    const list = document.getElementById("entries-list");
    list.innerHTML = "";
    if (data.entries.length === 0) {
        list.textContent = "Vault is empty.";
        return;
    }
    data.entries.forEach(entry => {
        const li = document.createElement("li");
        // textContent (not innerHTML) so a service name can never inject HTML
        li.textContent = entry.service + " — " + entry.username + " ";

        const del = document.createElement("button");
        del.textContent = "Delete";
        del.addEventListener("click", () => deleteEntry(entry.service, entry.username));
        li.appendChild(del);

        list.appendChild(li);
    });
}

async function deleteEntry(service, username) {
    if (!confirm("Delete " + username + " on " + service + "?")) {
        return;
    }
    const url = "/vault/entries/" + encodeURIComponent(service);
    const { ok, data } = await api(url, "DELETE", { password: masterPassword(), username: username });
    if (!ok) {
        showError(data.error);
        return;
    }
    loadEntries();
}

document.getElementById("add-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    if (!masterPassword()) {
        showError("Enter your master password first.");
        return;
    }
    const { ok, data } = await api("/vault/entries", "POST", {
        password: masterPassword(),
        service: document.getElementById("service").value,
        username: document.getElementById("username").value,
        entry_password: document.getElementById("password").value
    });
    if (!ok) {
        showError(data.error);
        return;
    }
    document.getElementById("add-form").reset();
    loadEntries();
});

document.getElementById("show-btn").addEventListener("click", loadEntries);
document.getElementById("logout-btn").addEventListener("click", logout);
document.getElementById("master-password").addEventListener("keydown", e => {
    if (e.key === "Enter") loadEntries();
});
