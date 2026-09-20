'use strict';
const video = document.querySelector('#walkthrough');
const chapters = document.querySelector('#chapter-buttons');
chapters.hidden = false;
chapters.addEventListener('click', event => {
  const button = event.target.closest('button[data-time]');
  if (!button) return;
  video.pause();
  const seek = () => { video.currentTime = Number(button.dataset.time) + 0.2; };
  if (video.readyState >= 1) seek();
  else { video.addEventListener('loadedmetadata', seek, { once: true }); video.load(); }
  chapters.querySelectorAll('button').forEach(item => item.removeAttribute('aria-current'));
  button.setAttribute('aria-current', 'true');
});
