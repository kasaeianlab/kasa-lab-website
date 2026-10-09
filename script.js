
document.getElementById('year')?.replaceChildren(
  document.createTextNode(new Date().getFullYear())
);

const menuButton = document.querySelector('.menu-toggle');
const nav = document.querySelector('.nav');

if (menuButton && nav) {
  menuButton.addEventListener('click', () => {
    const open = nav.classList.toggle('open');
    menuButton.setAttribute('aria-expanded', String(open));
  });
}

// Allow the contact form to submit to Formspree.
// Do not call preventDefault() here.
const contactForm = document.getElementById('contact-form');

if (contactForm) {
  contactForm.addEventListener('submit', () => {
    const note = document.getElementById('form-note');

    if (note) {
      note.textContent = 'Sending your message...';
      note.setAttribute('role', 'status');
    }
  });
}
