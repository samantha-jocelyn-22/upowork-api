const profileForm = document.querySelector("#profile-form");
const fileInput = document.querySelector("#cv-file");
const fileName = document.querySelector("#file-name");
const toast = document.querySelector("#toast");
const vacancySearch = document.querySelector("#vacancy-search");
const careerFilter = document.querySelector("#career-filter");
const loginForm = document.querySelector("#login-form");
const vacancyGrid = document.querySelector("#vacancy-grid");
let vacancies = [];

let csrfToken;
async function secureFetch(url, options = {}) {
  try {
    if (!csrfToken) {
      const tokenResponse = await fetch("/api/csrf-token");
      if (!tokenResponse.ok) throw new Error("No fue posible validar la sesión.");
      csrfToken = (await tokenResponse.json()).csrf_token;
    }
    const headers = new Headers(options.headers || {});
    headers.set("X-CSRF-Token", csrfToken);
    return await fetch(url, {...options, headers});
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error("No se pudo conectar con UPOwork. Comprueba tu conexión y vuelve a intentarlo.");
    }
    throw error;
  }
}

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[character]);
}

function showToast(message) {
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 3500);
}

fileInput?.addEventListener("change", () => {
  const file = fileInput.files[0];
  if (!file) {
    fileName.textContent = "Ningún archivo seleccionado";
    return;
  }
  if (file.type !== "application/pdf" || file.size > 5 * 1024 * 1024) {
    fileInput.value = "";
    fileName.textContent = "Ningún archivo seleccionado";
    showToast("El CV debe ser un PDF de máximo 5 MB.");
    return;
  }
  fileName.textContent = file.name;
});

profileForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  const formData = new FormData(profileForm);
  formData.append("cv", fileInput.files[0] || "");
  secureFetch("/api/profiles", { method: "POST", body: formData })
    .then(async (response) => {
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "No fue posible guardar el perfil.");
      showToast("Perfil guardado. Buscando vacantes relacionadas contigo...");
      window.setTimeout(() => { window.location.href = "dashboard.html"; }, 700);
    })
    .catch((error) => showToast(error.message));
});

function safeExternalUrl(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

function renderVacancies() {
  if (!vacancyGrid) return;
  const query = vacancySearch?.value.trim().toLowerCase() || "";
  const selectedCareer = careerFilter?.value || "all";
  const filtered = vacancies.filter((vacancy) => {
    const searchable = [vacancy.title, vacancy.company_name, vacancy.career, vacancy.description, vacancy.requirements]
      .join(" ").toLowerCase();
    return searchable.includes(query) && (selectedCareer === "all" || vacancy.career === selectedCareer);
  });
  vacancyGrid.innerHTML = filtered.length ? filtered.map((vacancy) => {
    const sourceUrl = safeExternalUrl(vacancy.source_url);
    const modeLabel = { presencial: "Presencial", hibrido: "Híbrido", remoto: "Remoto" }[vacancy.mode] || vacancy.mode;
    return `<article class="company-card vacancy-card">
      <div class="company-top"><span class="company-logo logo-coral">${escapeHtml(vacancy.company_name.slice(0, 1).toUpperCase())}</span><span class="tag tag-green">${escapeHtml(modeLabel)}</span></div>
      <p class="opportunity-type">${escapeHtml(vacancy.opportunity_type || "Oportunidad laboral")}</p>
      <h3>${escapeHtml(vacancy.title)}</h3><p class="company-area">${escapeHtml(vacancy.company_name)} · ${escapeHtml(vacancy.location || "Ubicación por definir")}</p>
      <p>${escapeHtml(vacancy.description)}</p><p class="vacancy-requirements"><strong>Requisitos:</strong> ${escapeHtml(vacancy.requirements || "Consulta el anuncio original.")}</p>
      <p class="vacancy-details">${escapeHtml(vacancy.career || "Todas las carreras")}${vacancy.deadline ? ` · Cierre: ${escapeHtml(vacancy.deadline)}` : ""}${vacancy.schedule ? ` · ${escapeHtml(vacancy.schedule)}` : ""}${vacancy.support ? ` · ${escapeHtml(vacancy.support)}` : ""}</p>
      ${sourceUrl ? `<a class="button button-small external-vacancy-link" href="${escapeHtml(sourceUrl)}" target="_blank" rel="noopener noreferrer nofollow">Ver anuncio y postularme <span>↗</span></a>` : "<p class='field-note'>El enlace del anuncio aún no está disponible.</p>"}
    </article>`;
  }).join("") : "<p class='empty-state'>No hay vacantes que coincidan. Prueba con otra búsqueda o carrera.</p>";
}

vacancySearch?.addEventListener("input", renderVacancies);
careerFilter?.addEventListener("change", renderVacancies);

async function loadVacancies() {
  if (!vacancyGrid) return;
  try {
    const response = await fetch("/api/vacancies");
    if (!response.ok) throw new Error("No fue posible cargar las vacantes.");
    vacancies = await response.json();
    renderVacancies();
  } catch (error) {
    console.error(error);
    vacancyGrid.innerHTML = "<p class='empty-state'>No fue posible cargar las vacantes. Intenta de nuevo más tarde.</p>";
  }
}
loadVacancies();
vacancyGrid?.addEventListener("click", async (event) => {
  const button = event.target.closest(".apply-vacancy");
  if (!button) return;
  const response = await secureFetch(`/api/vacancies/${button.dataset.id}/applications`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({})});
  const result = await response.json();
  showToast(response.ok ? "¡Postulación enviada!" : (result.error || "Inicia sesión como alumno para postularte."));
});

const menuToggle = document.querySelector(".menu-toggle");
const nav = document.querySelector(".main-nav");
menuToggle?.addEventListener("click", () => {
  const isOpen = nav.classList.toggle("open");
  menuToggle.setAttribute("aria-expanded", String(isOpen));
});
nav?.querySelectorAll("a").forEach((link) => link.addEventListener("click", () => {
  nav.classList.remove("open");
  menuToggle.setAttribute("aria-expanded", "false");
}));

document.querySelectorAll(".role-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".role-tab").forEach((item) => item.classList.remove("selected"));
    tab.classList.add("selected");
    document.querySelector("#login-form input[name='role']").value = tab.dataset.role;
  });
});

loginForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const response = await secureFetch("/api/login", { method: "POST", body: new FormData(loginForm) });
    const result = await response.json();
    if (!response.ok) {
      showToast(result.error);
      return;
    }
    window.location.href = "dashboard.html";
  } catch (error) {
    showToast(error.message);
  }
});
