const roleDescriptions = {
  student: "Aquí puedes consultar el estado de tu perfil y mantener tus datos actualizados.",
  teacher: "Desde aquí puedes revisar perfiles, dar seguimiento a postulaciones y publicar vacantes externas.",
  admin: "Desde aquí puedes administrar perfiles, postulaciones y vacantes de UPOwork."
};

let csrfToken;

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[character]);
}

function showToast(message) {
  const toast = document.querySelector("#toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 4000);
}

async function getCsrfToken() {
  if (csrfToken) return csrfToken;
  const response = await fetch("/api/csrf-token", { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error("No fue posible validar la sesión. Recarga la página.");
  csrfToken = (await response.json()).csrf_token;
  return csrfToken;
}

async function secureFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("X-CSRF-Token", await getCsrfToken());
  headers.set("Accept", "application/json");
  return fetch(url, { ...options, headers });
}

async function jsonOrError(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "No se pudo completar la solicitud.");
  return data;
}

function safeExternalUrl(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ? url.href : "";
  } catch { return ""; }
}

function renderNotifications(items) {
  const container = document.querySelector("#notification-list");
  if (!container) return;
  container.innerHTML = items.length
    ? items.map((item) => `<div class="notification-item ${item.read_at ? "" : "unread"}"><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.message)}</span></div>`).join("")
    : "<p>No tienes avisos nuevos.</p>";
}

function renderRecommendations(items) {
  const container = document.querySelector("#recommendation-list");
  if (!container) return;
  container.innerHTML = items.length ? items.map((item) => {
    const url = safeExternalUrl(item.source_url);
    return `<article class="recommendation-card"><div class="recommendation-card-top"><span class="tag tag-green">Coincide con tu perfil</span><span>${escapeHtml(item.mode || "")}</span></div>
      <h3>${escapeHtml(item.title)}</h3><p><strong>${escapeHtml(item.company_name)}</strong> · ${escapeHtml(item.location || "Ubicación por definir")}</p>
      <small>${escapeHtml((item.match_reasons || []).join(" · "))}</small>
      ${url ? `<a class="button button-small external-vacancy-link" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">Ver anuncio original ↗</a>` : `<button class="button button-small apply-recommendation" data-id="${Number(item.id)}">Postularme →</button>`}
    </article>`;
  }).join("") : "<p>Aún no hay vacantes recomendadas. Vuelve a revisar más tarde.</p>";
}

async function loadStudentDashboard() {
  const panel = document.querySelector("#student-panel");
  panel.hidden = false;
  if (!panel.querySelector(".student-suggestion-link")) {
    const link = document.createElement("p");
    link.className = "student-suggestion-link";
    link.innerHTML = '<a class="button button-small" href="/sugerencias">Enviar una sugerencia</a>';
    panel.prepend(link);
  }
  const [profileResponse, applicationsResponse, notificationsResponse, recommendationsResponse] = await Promise.all([
    fetch("/api/profile"), fetch("/api/applications"), fetch("/api/notifications"), fetch("/api/recommendations")
  ]);
  const profile = profileResponse.ok ? await profileResponse.json() : null;
  const applications = applicationsResponse.ok ? await applicationsResponse.json() : [];
  const notifications = notificationsResponse.ok ? await notificationsResponse.json() : [];
  const recommendations = recommendationsResponse.ok ? await recommendationsResponse.json() : [];
  document.querySelector("#own-profile").innerHTML = profile
    ? `<div><b>Correo</b><span>${escapeHtml(profile.email)}</span></div><div><b>Carrera</b><span>${escapeHtml(profile.career)}</span></div><div><b>Interés</b><span>${escapeHtml(profile.interest)}</span></div><div><b>Habilidades</b><span>${escapeHtml(profile.skills)}</span></div>`
    : '<p>Aún no tienes perfil. <a href="/perfil">Créalo aquí.</a></p>';
  renderNotifications(notifications);
  renderRecommendations(recommendations);
  document.querySelector("#application-list").innerHTML = applications.length
    ? applications.map((item) => `<div><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.company_name)} · ${escapeHtml(item.status)}</span></div>`).join("")
    : "<p>Aún no tienes postulaciones.</p>";
}

async function loadStaffDashboard(user) {
  document.querySelector("#directory-panel").hidden = false;
  const [studentsResponse, applicationsResponse, vacanciesResponse] = await Promise.all([
    fetch("/api/students"), fetch("/api/applications"), fetch("/api/my-vacancies")
  ]);
  const students = await jsonOrError(studentsResponse);
  const applications = await jsonOrError(applicationsResponse);
  const vacancies = await jsonOrError(vacanciesResponse);
  document.querySelector("#student-list").innerHTML = students.length ? students.map((student) => `
    <tr><td><strong>${escapeHtml(student.name)}</strong><small>${escapeHtml(student.email)}</small></td>
    <td>${escapeHtml(student.career)}</td><td>${escapeHtml(student.interest)}</td><td>${escapeHtml(student.skills)}</td>
    <td>${student.cv_filename ? `<a class="table-link" href="/api/students/${Number(student.id)}/cv">Descargar CV</a>` : "Sin CV"}</td>
    <td><span>${escapeHtml(student.approval_status || "pending")}</span><button class="button button-small approve-student" data-id="${Number(student.id)}" type="button">Aprobar</button>
    <button class="button button-small delete-student" data-id="${Number(student.id)}" type="button">Eliminar</button></td></tr>`).join("") : '<tr><td colspan="6">Aún no hay perfiles registrados.</td></tr>';
  document.querySelector("#managed-applications").innerHTML = applications.length
    ? applications.map((item) => `<div><b>${escapeHtml(item.student_name || "Alumno")}</b><span>${escapeHtml(item.title)} · ${escapeHtml(item.status)}</span></div>`).join("")
    : "<p>Aún no hay postulaciones.</p>";
  const vacancyManagement = document.querySelector("#vacancy-management");
  if (vacancyManagement) vacancyManagement.innerHTML = vacancies.length ? vacancies.map((item) => `
    <div><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.company_name)} · ${escapeHtml(item.status)}</span>
    ${item.status === "active" ? `<button class="button button-small close-vacancy" data-id="${Number(item.id)}" type="button">Cerrar vacante</button>` : ""}</div>`).join("") : "<p>No hay vacantes publicadas.</p>";
  if (user.role === "teacher" || user.role === "admin") {
    const response = await fetch("/api/suggestions");
    const suggestions = response.ok ? await response.json() : [];
    const target = document.querySelector("#teacher-suggestion-list");
    if (target) target.innerHTML = suggestions.length
      ? suggestions.map((item) => `<div class="review-item"><b>${escapeHtml(item.subject)}</b><span>${escapeHtml(item.category)} · ${escapeHtml(item.student_name)} · ${escapeHtml(item.created_at)}</span><p>${escapeHtml(item.message)}</p></div>`).join("")
      : "<p>Aún no se han recibido sugerencias.</p>";
  }
}

async function loadDashboard() {
  const response = await fetch("/api/me", { headers: { Accept: "application/json" } });
  if (!response.ok) { window.location.assign("/login"); return; }
  const user = await response.json();
  document.querySelector("#user-name").textContent = user.name;
  document.querySelector("#role-description").textContent = roleDescriptions[user.role] || roleDescriptions.student;
  if (user.role === "student") await loadStudentDashboard();
  else await loadStaffDashboard(user);
}

const logoutButton = document.querySelector("#logout-button");
logoutButton?.addEventListener("click", async () => {
  logoutButton.disabled = true;
  try {
    await jsonOrError(await secureFetch("/api/logout", { method: "POST" }));
    // Flask serves the login page at /login; /login.html does not exist.
    window.location.assign("/login");
  } catch (error) { showToast(error.message); logoutButton.disabled = false; }
});

document.querySelector("#export-students")?.addEventListener("click", () => window.location.assign("/api/students/export"));

document.querySelector("#recommendation-list")?.addEventListener("click", async (event) => {
  const button = event.target.closest(".apply-recommendation");
  if (!button) return;
  try {
    const response = await secureFetch(`/api/vacancies/${button.dataset.id}/applications`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    const result = await jsonOrError(response);
    showToast(result.message || "Postulación enviada.");
    await loadDashboard();
  } catch (error) { showToast(error.message); }
});

document.querySelector("#student-list")?.addEventListener("click", async (event) => {
  const approve = event.target.closest(".approve-student");
  const remove = event.target.closest(".delete-student");
  try {
    if (approve) {
      const response = await secureFetch(`/api/students/${approve.dataset.id}/approval`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: "approved" }) });
      showToast((await jsonOrError(response)).message);
      await loadDashboard();
    } else if (remove && window.confirm("¿Eliminar el perfil de este alumno?")) {
      const response = await secureFetch(`/api/students/${remove.dataset.id}`, { method: "DELETE" });
      showToast((await jsonOrError(response)).message);
      await loadDashboard();
    }
  } catch (error) { showToast(error.message); }
});

document.querySelector("#vacancy-management")?.addEventListener("click", async (event) => {
  const button = event.target.closest(".close-vacancy");
  if (!button) return;
  try {
    const response = await secureFetch(`/api/vacancies/${button.dataset.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: "closed" }) });
    showToast((await jsonOrError(response)).message);
    await loadDashboard();
  } catch (error) { showToast(error.message); }
});

document.querySelector("#vacancy-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const response = await secureFetch("/api/vacancies", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(form))) });
    const result = await jsonOrError(response);
    showToast(result.message || "Oportunidad publicada.");
    form.reset();
    await loadDashboard();
  } catch (error) { showToast(error.message); }
});

loadDashboard().catch((error) => { console.error(error); showToast(error.message || "No fue posible cargar tu cuenta."); });
