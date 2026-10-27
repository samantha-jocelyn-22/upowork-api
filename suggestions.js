const form = document.querySelector("#suggestion-form");
const toast = document.querySelector("#toast");
let csrfToken;

fetch("/api/me").then((response) => {
  if (!response.ok) window.location.href = "login.html";
  else return response.json();
}).then((user) => {
  if (user && user.role !== "student") window.location.href = "login.html";
}).catch(() => {
  toast.textContent = "No fue posible validar tu sesión. Inicia sesión e inténtalo de nuevo.";
  toast.classList.add("show");
});

async function secureFetch(url, options = {}) {
  if (!csrfToken) {
    const tokenResponse = await fetch("/api/csrf-token");
    if (!tokenResponse.ok) throw new Error("No fue posible validar tu sesión.");
    csrfToken = (await tokenResponse.json()).csrf_token;
  }
  const headers = new Headers(options.headers || {});
  headers.set("X-CSRF-Token", csrfToken);
  return fetch(url, {...options, headers});
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    const response = await secureFetch("/api/suggestions", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.fromEntries(new FormData(form)))
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "No fue posible enviar la sugerencia.");
    toast.textContent = result.message;
    toast.classList.add("show");
    form.reset();
  } catch (error) {
    toast.textContent = error.message;
    toast.classList.add("show");
  } finally {
    button.disabled = false;
  }
});
