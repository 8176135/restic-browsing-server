const form = document.querySelector("form");
const submit_btn = document.querySelector("#form_submit_btn");
const conf_password = document.querySelector("#pass_conf");


function validation() {
    if (document.getElementById("password").value === document.getElementById("pass_conf").value) {
        document.getElementById("pass_conf").setCustomValidity("Passwords don't match");
        return true;
    } else {
        document.getElementById("pass_conf").setCustomValidity("");
        return false;
    }
}

conf_password.addEventListener("input", function (ev) {
    if (document.getElementById("password").value !== document.getElementById("pass_conf").value) {
        this.setCustomValidity('Password Must be Matching.');
    } else {
        this.setCustomValidity('');
    }
});


form.addEventListener("submit", function (ev) {
    if(!this.checkValidity() || !validation())
    {
        ev.preventDefault();
    }
});

// submit_btn.addEventListener("click", () => {
//    if (form.checkValidity()) {
//
//    }
// });