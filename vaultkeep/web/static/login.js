// Login page: exchange the master password for a short-lived JWT.
document.getElementById("login-form").addEventListener("submit", async function (e) {
    e.preventDefault(); // prevent page refresh

    const errorBox = document.getElementById("error-message");
    errorBox.textContent = "";

    let response, data;
    try {
        response = await fetch("/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: document.getElementById("password").value })
        });
        data = await response.json();
    } catch (err) {
        errorBox.textContent = "Could not reach the server.";
        return;
    }

    if (response.ok && data.token) {
        localStorage.setItem("token", data.token);
        window.location.href = "/dashboard";
    } else if (response.status === 429) {
        errorBox.textContent = data.error; // rate limited
    } else {
        errorBox.textContent = "Invalid password. Try again.";
    }
});
