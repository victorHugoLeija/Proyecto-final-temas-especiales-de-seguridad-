document.addEventListener('DOMContentLoaded', ()=>{
    const form = document.getElementById('lead-form');
    if(!form) return;
    const message = document.getElementById('lead-message');

    function sanitize(s){
        return String(s||'').replace(/[<>"'`]/g,'');
    }

    form.addEventListener('submit', (e)=>{
        e.preventDefault();
        const name = sanitize(document.getElementById('lead-name').value.trim());
        const phone = sanitize(document.getElementById('lead-phone').value.trim());
        const email = sanitize(document.getElementById('lead-email').value.trim());
        const eventType = sanitize(document.getElementById('lead-event').value);
        const space = sanitize(document.getElementById('lead-space').value);
        const people = parseInt(document.getElementById('lead-people').value)||0;

        if(!name || !phone || !email){
            message.textContent = 'Por favor completa nombre, teléfono y correo.'; message.className='form-message error'; return;
        }
        if(!/^\+?[0-9\s\-]{7,}$/.test(phone)){
            message.textContent = 'Teléfono no válido.'; message.className='form-message error'; return;
        }
        if(!/^\S+@\S+\.\S+$/.test(email)){
            message.textContent = 'Correo no válido.'; message.className='form-message error'; return;
        }

        const leads = JSON.parse(localStorage.getItem('dj_leads')||'[]');
        leads.push({name,phone,email,eventType,space,people,timestamp:Date.now()});
        localStorage.setItem('dj_leads', JSON.stringify(leads));

        message.textContent = `¡Gracias ${name}! Recibimos tu solicitud. Te contactamos pronto.`; message.className='form-message success';
        form.reset();
        setTimeout(()=>{ message.className='form-message'; message.textContent=''; },4000);
    });
});
