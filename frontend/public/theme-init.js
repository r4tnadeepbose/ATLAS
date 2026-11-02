try {
  if (localStorage.getItem("atlas.theme") === "light") {
    document.documentElement.classList.add("light");
    document.documentElement.dataset.theme = "light";
  }
} catch (error) {
  /* ignore unavailable storage */
}
