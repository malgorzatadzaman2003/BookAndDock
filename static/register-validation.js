document.addEventListener("DOMContentLoaded", function() {
    const form = document.getElementById("register-form");
    form.addEventListener("submit", function(event) {
        let errors = [];
        const username = form.querySelector("#id_username").value;
        const email = form.querySelector("#id_email").value;
        const password1 = form.querySelector("#id_password1").value;
        const password2 = form.querySelector("#id_password2").value;

        if (username.length < 3) {
            errors.push("Username must be at least 3 characters long.");
        }

        if (!email.includes("@")) {
            errors.push("Please enter a valid email address.");
        }

        if (password1.length < 8) {
            errors.push("Password must be at least 8 characters long.");
        }

        if (password1 !== password2) {
            errors.push("Passwords do not match.");
        }

        if (errors.length > 0) {
            event.preventDefault();  // Prevent form submission
            document.getElementById("error-message").innerHTML = errors.join("<br>");
        }
    });
});
