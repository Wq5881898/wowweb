const tabButtons = document.querySelectorAll("[data-auth-tab]");
const authPanels = document.querySelectorAll("[data-auth-panel]");

tabButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const target = button.dataset.authTab;

    tabButtons.forEach((item) => {
      item.classList.toggle("active", item === button);
    });

    authPanels.forEach((panel) => {
      panel.classList.toggle("hidden", panel.dataset.authPanel !== target);
    });
  });
});
