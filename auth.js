const AUTH_STORAGE_SESSION = 'site_session';

function getSession() {
    try {
        return JSON.parse(localStorage.getItem(AUTH_STORAGE_SESSION) || 'null');
    } catch (err) {
        return null;
    }
}

function setSession(email, token, role = 'user') {
    const session = {
        email: email.trim().toLowerCase(),
        token,
        role,
        loggedAt: new Date().toISOString()
    };

    localStorage.setItem(AUTH_STORAGE_SESSION, JSON.stringify(session));
    return session;
}

function clearSession() {
    localStorage.removeItem(AUTH_STORAGE_SESSION);
}

function renderAuthLink() {
    const authItem = document.getElementById('nav-auth');
    if (!authItem) return;

    const session = getSession();

    if (session && session.email && session.token) {
        authItem.innerHTML = session.role === 'admin'
            ? '<a href="admin.html">ADMIN</a> <a href="#" id="logout-link">CERRAR SESIÓN</a>'
            : '<a href="#" id="logout-link">CERRAR SESIÓN</a>';

        const logoutLink = document.getElementById('logout-link');
        if (logoutLink) {
            logoutLink.addEventListener('click', (event) => {
                event.preventDefault();
                clearSession();
                renderAuthLink();
                window.location.href = 'index.html';
            });
        }
    } else {
        authItem.innerHTML = '<a href="login.html">INGRESAR</a>';
    }
}

document.addEventListener('DOMContentLoaded', renderAuthLink);
