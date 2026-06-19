const form = document.querySelector("#registerForm");
const statusMessage = document.querySelector("#statusMessage");
const submitButton = document.querySelector("#submitButton");

function showMessage(type, text) {
  statusMessage.hidden = false;
  statusMessage.className = `status-message ${type}`;
  statusMessage.textContent = text;
}

function validateClientSide(formData) {
  const username = (formData.get("username") || "").trim();
  const password = formData.get("password") || "";
  const confirmPassword = formData.get("confirm_password") || "";
  const email = (formData.get("email") || "").trim();

  if (!/^[A-Za-z0-9_]{3,16}$/.test(username)) {
    return "账号名必须为 3 到 16 位，只能包含英文字母、数字和下划线。";
  }

  if (password.length < 6 || password.length > 32 || /\s/.test(password)) {
    return "密码必须为 6 到 32 位，并且不能包含空格。";
  }

  if (password !== confirmPassword) {
    return "两次输入的密码不一致。";
  }

  if (email && (/\s/.test(email) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
    return "邮箱格式不正确。";
  }

  return "";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(form);
  const validationError = validateClientSide(formData);
  if (validationError) {
    showMessage("error", validationError);
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = "正在注册...";

  try {
    const response = await fetch(form.action, {
      method: "POST",
      body: formData,
      headers: { Accept: "application/json" },
    });
    const result = await response.json();

    if (!response.ok || !result.ok) {
      showMessage("error", result.message || "注册失败，请联系管理员。");
      return;
    }

    showMessage("success", result.message);
    form.reset();
  } catch (error) {
    showMessage("error", "服务器注册服务暂时不可用。");
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "注册账号";
  }
});
