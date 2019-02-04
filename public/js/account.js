function setInputFilter(textbox, inputFilter) {
    ["input", "keydown", "keyup", "mousedown", "mouseup", "select", "contextmenu", "drop"].forEach(function (event) {
        textbox.addEventListener(event, function () {
            if (inputFilter(this.value)) {
                this.oldValue = this.value;
                this.oldSelectionStart = this.selectionStart;
                this.oldSelectionEnd = this.selectionEnd;
            } else if (this.hasOwnProperty("oldValue")) {
                this.value = this.oldValue;
                this.setSelectionRange(this.oldSelectionStart, this.oldSelectionEnd);
            }
        });
    });
}

let secret = null;

$(document).ready(function () {
    $('.collapsible').collapsible();
    $('.modal').modal();
    $('.message_popup').modal("open");

    $("#two_fa_success").modal({
        onCloseStart: function () {
            location.reload()
        } // Callback for Modal close
    });

    $("#enable2fa").click((ev) => {
        $("#qrcode").empty();
        $.ajax({
            url: "change/2fa/enable",
            type: "POST",
            success: function (res) {
                new QRCode(document.getElementById("qrcode"),
                    {
                        text: "otpauth://totp/RBS:account@rbs.handofcthulhu.com?secret=" + res + "&issuer=RBS",
                        width: 256,
                        height: 256,
                        correctLevel: QRCode.CorrectLevel.H
                    });
                $("#secret_code").text(res);
                secret = res;
                $("#two_fa_confirm").modal("open");
            },
            error: function (jqXHR, textStatus, errorThrown) {
                console.log(jqXHR);
                console.log(textStatus);
                console.log(errorThrown);
            }
        });
    });
    const confirm_input = $("#auth_code_confirm");
    $("#confirm_2fa_btn").click((ev) => {
        if (confirm_input[0].checkValidity()) {
            $.ajax({
                url: "change/2fa/confirm",
                type: "POST",
                success: function () {
                    $("#two_fa_success").modal("open");
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    switch (jqXHR.status) {
                        case 401:
                            $("#two_fa_confirm .status").text("Invalid 2FA code, try again?");
                            break;
                        case 406:
                            $("#two_fa_confirm .status").text("2FA has already been activated");
                            break;
                    }
                    console.log(jqXHR);
                    console.log(textStatus);
                    console.log(errorThrown);
                },
                data: JSON.stringify({
                    auth_code_confirm: confirm_input.val(),
                    secret: secret,
                }),
            });
        } else {
            confirm_input[0].reportValidity();
        }
    });
    $("#disable2fa").click((ev) => {
        $.ajax({
            url: "change/2fa/disable",
            type: "POST",
            data: "auth_code=" + $("#auth_code").val(),
            success: function () {
                $("#two_fa_success").modal("open");
            },
            error: function (jqXHR, textStatus, errorThrown) {
                switch (jqXHR.status) {
                    case 401:
                        $("#disable_2fa_status.status").text("Invalid 2FA code, try again?");
                        break;
                    case 406:
                        $("#disable_2fa_status.status").text("2FA has already been deactivated");
                        break;
                }
                console.log(jqXHR);
                console.log(textStatus);
                console.log(errorThrown);
            }
        });
    });


    setInputFilter(confirm_input[0], function (value) {
        return /^\d*$/.test(value);
    })
});