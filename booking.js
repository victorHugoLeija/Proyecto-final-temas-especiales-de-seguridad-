document.addEventListener('DOMContentLoaded', ()=>{
    const calculateBtn = document.getElementById('calculate');
    const whatsappQuote = document.getElementById('whatsapp-quote');
    if(!calculateBtn) return;

    function extrasCost(){
        const extras = ['extra-speaker','extra-booth','extra-lights','extra-pyro','extra-co2','extra-haze','extra-lasers','extra-heads'];
        let sum = 0;
        extras.forEach(id=>{ const el = document.getElementById(id); if(el && el.checked){
            if(id==='extra-speaker') sum += 1200;
            else if(id==='extra-booth') sum += 1500;
            else if(id==='extra-lights') sum += 2000;
            else if(id==='extra-pyro') sum += 3500;
            else if(id==='extra-co2') sum += 1500;
            else if(id==='extra-haze') sum += 900;
            else if(id==='extra-lasers') sum += 3000;
            else if(id==='extra-heads') sum += 4500;
        }});
        return sum;
    }

    function basePriceForPeople(n){
        if(n<=0) return 0;
        if(n<=100) return 5500;
        if(n<=200) return 5500 + 3000;
        if(n<=300) return 5500 + 5500;
        return 5500 + 7500;
    }

    calculateBtn.addEventListener('click', ()=>{
        const people = parseInt(document.getElementById('c-people').value) || 0;
        const hours = parseInt(document.getElementById('c-hours').value) || 5;
        const base = basePriceForPeople(people);
        const perExtra = extrasCost();
        const extraHours = Math.max(0, hours - 5);
        const hoursCost = extraHours * 1200;
        const total = base + perExtra + hoursCost;

        document.getElementById('price-base').textContent = `$${base.toLocaleString()}`;
        document.getElementById('price-extras').textContent = `$${perExtra.toLocaleString()} (+ horas $${hoursCost.toLocaleString()})`;
        document.getElementById('price-total').textContent = `$${total.toLocaleString()}`;
    });

    whatsappQuote.addEventListener('click', (e)=>{
        e.preventDefault();
        const phone = '5212345678900';
        const text = encodeURIComponent('Solicito cotización para evento fuera de CDMX. ');
        window.open('https://wa.me/'+phone+'?text='+text, '_blank');
    });
});
