const roleDescriptions = {
  student: "Aquí puedes consultar el estado de tu perfil y mantener tus datos actualizados.",
  teacher: "Desde aquí puedes revisar perfiles, dar seguimiento a postulaciones y publicar vacantes externas para las carreras UPOTec."
};

function escapeHtml(value = "") {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[character]);
}

function showToast(message) {
  const toast = document.querySelector("#toast");
  toast.textContent = message;
  toast.classList.add("show");
}

let csrfToken;
async function secureFetch(url, options = {}) {
  try {
    if (!csrfToken) {
      const tokenResponse = await fetch("/api/csrf-token");
      if (!tokenResponse.ok) throw new Error("No fue posible validar tu sesión.");
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

function renderRecommendations(recommendations) {
  const container = document.querySelector("#recommendation-list");
  if (!container) return;
  container.innerHTML = recommendations.length
    ? recommendations.map((item) => `
      <article class="recommendation-card">
        <div class="recommendation-card-top"><span class="tag tag-green">Coincide con tu perfil</span><span>${escapeHtml(item.mode)}</span></div>
        <h3>${escapeHtml(item.title)}</h3>
        <p><strong>${escapeHtml(item.company_name)}</strong> · ${escapeHtml(item.location || "Ubicación por definir")}</p>
        <small>${escapeHtml(item.match_reasons.join(" · "))}</small>
        ${safeExternalUrl(item.source_url)
          ? `<a class="button button-small external-vacancy-link" href="${escapeHtml(safeExternalUrl(item.source_url))}" target="_blank" rel="noopener noreferrer nofollow">Ver anuncio y postularme <span>↗</span></a>`
          : `<button class="button button-small apply-recommendation" data-id="${item.id}">Postularme <span>→</span></button>`}
      </article>`).join("")
    : "<p>Aún no encontramos una vacante que coincida claramente con tu carrera, interés o habilidades.</p>";
}

function safeExternalUrl(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

function renderNotifications(notifications) {
  const container = document.querySelector("#notification-list");
  if (!container) return;
  container.innerHTML = notifications.length
    ? notifications.map((item) => `<div class="notification-item ${item.read_at ? "" : "unread"}"><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.message)}</span></div>`).join("")
    : "<p>No tienes avisos nuevos.</p>";
}

async function loadDashboard() {
  const response = await fetch("/api/me");
  if (!response.ok) {
    window.location.href = "login.html";
    return;
  }
  const user = await response.json();
  document.querySelector("#user-name").textContent = user.name;
  document.querySelector("#role-description").textContent = roleDescriptions[user.role];
  if (user.role === "student") {
    document.querySelector("#student-panel").hidden = false;
    document.querySelector("#student-panel").insertAdjacentHTML(
      "afterbegin",
      `<p class="student-suggestion-link"><a class="button button-small" href="sugerencias.html">Enviar una sugerencia</a></p>`
    );
    const profile = await (await fetch("/api/profile")).json();
    document.querySelector("#own-profile").innerHTML = profile
      ? `<div><b>Correo</b><span>${escapeHtml(profile.email)}</span></div><div><b>Carrera</b><span>${escapeHtml(profile.career)}</span></div><div><b>Interés</b><span>${escapeHtml(profile.interest)}</span></div><div><b>Habilidades</b><span>${escapeHtml(profile.skills)}</span></div><div><b>CV</b><span>${profile.cv_filename ? escapeHtml(profile.cv_filename) : "Aún no adjuntado"}</span></div><div><b>Estado</b><span>${escapeHtml(profile.approval_status || "pending")}</span></div>`
      : "<p>Aún no tienes un perfil profesional. <a href='perfil.html'>Créalo aquí.</a></p>";
    const applications = await (await fetch("/api/applications")).json();
    const notificationsResponse = await fetch("/api/notifications");
    renderNotifications(notificationsResponse.ok ? await notificationsResponse.json() : []);
    const recommendationsResponse = await fetch("/api/recommendations");
    const recommendations = recommendationsResponse.ok ? await recommendationsResponse.json() : [];
    renderRecommendations(recommendations);
    document.querySelector("#application-list").innerHTML = applications.length
      ? applications.map((item) => `<div><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.company_name)} · ${escapeHtml(item.status)}</span></div>`).join("")
      : "<p>Aún no tienes postulaciones.</p>";
    return;
  }
  document.querySelector("#directory-panel").hidden = false;
  const studentsResponse = await fetch("/api/students");
  if (!studentsResponse.ok) throw new Error("No fue posible cargar los perfiles autorizados.");
  const students = await studentsResponse.json();
  document.querySelector("#student-list").innerHTML = students.length ? students.map((student) => `<tr><td><strong>${escapeHtml(student.name)}</strong><small>${escapeHtml(student.email)}</small></td><td>${escapeHtml(student.career)}</td><td>${escapeHtml(student.interest)}</td><td>${escapeHtml(student.skills)}</td><td>${student.cv_filename ? `<a class="table-link" href="/api/students/${student.id}/cv">Descargar PDF</a>` : "No adjunto"}</td><td><button class="delete-student" data-id="${student.id}">Eliminar</button><button class="approve-student" data-id="${student.id}">${escapeHtml(student.approval_status || "pending")}</button></td></tr>`).join("") : "<tr><td colspan='6'>Todavía no hay perfiles registrados.</td></tr>";
  const applications = await (await fetch("/api/applications")).json();
  document.querySelector("#managed-applications").innerHTML = applications.length
    ? applications.map((item) => `<div><b>${escapeHtml(item.student_name)}</b><span>${escapeHtml(item.title)} · ${escapeHtml(item.status)} ${user.role !== "teacher" ? `<button class="application-status" data-id="${item.id}">Marcar en revisión</button>` : ""}</span></div>`).join("")
    : "<p>Aún no hay postulaciones.</p>";
  const vacanciesResponse = await fetch("/api/my-vacancies");
  if (!vacanciesResponse.ok) throw new Error("No fue posible cargar las vacantes.");
  const vacancies = await vacanciesResponse.json();
  const vacancyManagement = document.querySelector("#vacancy-management");
  if (vacancyManagement) vacancyManagement.innerHTML = vacancies.length
    ? vacancies.map((item) => `<div><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.company_name)} · ${escapeHtml(item.status)} ${safeExternalUrl(item.source_url) ? `<a class="table-link" href="${escapeHtml(safeExternalUrl(item.source_url))}" target="_blank" rel="noopener noreferrer">Ver anuncio</a>` : ""} <button class="close-vacancy" data-id="${item.id}">Cerrar</button></span></div>`).join("")
    : "<p>No hay vacantes publicadas.</p>";
  if (user.role === "teacher") {
    const panel = document.querySelector("#directory-panel");
    if (!panel.querySelector("#teacher-review-tools")) {
      panel.insertAdjacentHTML("beforeend", `<section id="teacher-review-tools">
        <div class="panel-title"><h2>Sugerencias de alumnos</h2></div>
        <div id="teacher-suggestion-list" class="profile-summary"></div>
      </section>`);
    }
    const suggestionsResponse = await fetch("/api/suggestions");
    if (!suggestionsResponse.ok) throw new Error("No fue posible cargar las sugerencias.");
    const suggestions = suggestionsResponse.ok ? await suggestionsResponse.json() : [];
    document.querySelector("#teacher-suggestion-list").innerHTML = suggestions.length
      ? suggestions.map((item) => `<div class="review-item"><b>${escapeHtml(item.subject)}</b><span>${escapeHtml(item.category)} · ${escapeHtml(item.student_name)} · ${escapeHtml(item.created_at)}</span><p>${escapeHtml(item.message)}</p><label>Seguimiento<select class="suggestion-status" data-id="${item.id}"><option value="new" ${item.status === "new" ? "selected" : ""}>Nueva</option><option value="reviewing" ${item.status === "reviewing" ? "selected" : ""}>En revisión</option><option value="resolved" ${item.status === "resolved" ? "selected" : ""}>Atendida</option></select></label></div>`).join("")
      : "<p>Aún no se han recibido sugerencias.</p>";
  }
}

document.querySelector("#logout-button").addEventListener("click", async () => {
  await secureFetch("/api/logout", { method: "POST" });
  window.location.href = "login.html";
});

document.querySelector("#export-students")?.addEventListener("click", () => {
  window.location.href = "/api/students/export";
});

document.querySelector("#recommendation-list")?.addEventListener("click", async (event) => {
  const button = event.target.closest(".apply-recommendation");
  if (!button) return;
  const response = await secureFetch(`/api/vacancies/${button.dataset.id}/applications`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({})
  });
  const result = await response.json();
  showToast(response.ok ? "Postulación enviada." : (result.error || "No fue posible enviar la postulación."));
  if (response.ok) await loadDashboard();
});
loadDashboard().catch(() => showToast("No fue posible cargar tu cuenta."));

document.querySelector("#student-list")?.addEventListener("click", async (event) => {
  const approval = event.target.closest(".approve-student");
  if (approval) {
    const response = await secureFetch(`/api/students/${approval.dataset.id}/approval`, { method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify({status: "approved"}) });
    if (response.ok) await loadDashboard();
    return;
  }
  const button = event.target.closest(".delete-student");
  if (!button || !window.confirm("Se eliminará el perfil y la cuenta del alumno. ¿Continuar?")) return;
  const response = await secureFetch(`/api/students/${button.dataset.id}`, { method: "DELETE" });
  const result = await response.json();
  if (!response.ok) {
    showToast(result.error || "No fue posible eliminar la cuenta.");
    return;
  }
  showToast(result.message);
  await loadDashboard();
});

document.querySelector("#directory-panel")?.addEventListener("change", async (event) => {
  const select = event.target.closest(".suggestion-status");
  if (!select) return;
  const response = await secureFetch(`/api/suggestions/${select.dataset.id}`, {
    method: "PATCH",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({status: select.value})
  });
  const result = await response.json();
  if (!response.ok) showToast(result.error || "No fue posible actualizar la sugerencia.");
  else showToast("Seguimiento actualizado.");
});

document.querySelector("#vacancy-management")?.addEventListener("click", async (event) => {
    const button = event.target.closest(".close-vacancy");
    if (!button) return;
    try {
      const response = await secureFetch(`/api/vacancies/${button.dataset.id}`, {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify({status: "closed"})});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "No fue posible cerrar la vacante.");
      await loadDashboard();
    } catch (error) {
      showToast(error.message);
    }
  });

document.querySelector("#vacancy-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const response = await secureFetch("/api/vacancies", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(Object.fromEntries(new FormData(form)))});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "No fue posible publicar la vacante.");
    showToast("Oportunidad publicada.");
    form.reset();
    await loadDashboard();
  } catch (error) {
    showToast(error.message);
  }
});
