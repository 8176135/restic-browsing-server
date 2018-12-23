// $(".edit").click((ev) => {
//     //$("#edit_repo_modal").modal();
//
//     console.log($(ev.target).attr("data-for"));
// });

let counter = 0;

function adding_options(target, selected_data) {
    counter++;
    let list_item = $(`<li class="collection-item line black"></li>`);
    let env_name_template = $("#env_name_template").clone();
    env_name_template.removeAttr("id");
    env_name_template.removeClass("browser-default");
    list_item.append(env_name_template);
    list_item.append(`
                <div class="input-field">
                    <input type="text" name="env_value_list" id="env_value_${counter}" autocomplete="nope" maxlength="180" required>
                    <label for="env_value_${counter}">Env-var Value</label>
                </div>`);
    let del_btn = $(`<button class="btn btn-flat waves-effect waves-dark white-text delete" type="button"><i class="material-icons">delete</i></button>`);
    del_btn.click((ev2) => {
        $(ev2.target).parents(".collection-item").remove();
    });
    list_item.append(del_btn);
    $(target).parent().before(list_item);

    if (selected_data) {
        env_name_template.val(selected_data);
        list_item.find(`#env_value_${counter}`)
            .attr("placeholder", "[Same Value]")
            .removeAttr("required");
    }
    env_name_template.formSelect();
}

$(".env_variable_list").each((idx, c) => {
    let temp = $(c).attr("data-preloaded");
    if (temp) {
        let array = temp.split(",");
        for (let i = 0; i < array.length; i++) {
            adding_options($(c).find("button").get(0), array[i]);
        }
    }
});
$("select.preselect").each((idx, c) => {
    $(c).find("option[value='" + $(c).attr("data-selected") + "']").prop("selected", true);
});

$(document).ready(function () {
    $('.modal').modal();
    $('.message_popup').modal("open");
    $('.tabs').tabs();
    $('select').formSelect();
    $('.repo_name').click((ev) => {
        let line = $(ev.target).parents(".line");
        line.hide();
        line.parents(".collection-item").find(".progress").removeClass("invisible");
    });

    if ($(".service_list_item").length === 0) {
        let btn = $("#add_new_repo_modal_btn");
        btn.prop("disabled", true);

        btn.parent().tooltip();
    }
    // let list = $("#new_env_variable_list");

    $('.add_var_btn').click((ev) => {
        adding_options(ev.target);
    });
    const delete_service_confirm_modal = $("#delete_service_confirm_modal");
    const delete_config_confirm_modal = $("#delete_config_confirm_modal");
    let last_confirm_url;
    $("#service_list_content .delete.btn").click((ev) => {
        let delete_url = $(ev.target).attr("data-delete_name");
        last_confirm_url = delete_url;
        delete_service_confirm_modal.find(".service_name").text(decodeURIComponent(delete_url.replace(/\+/g, ' ')));
        delete_service_confirm_modal.attr("action", "/delete/service/" + delete_url)
    });

    $("#repo_list_content .delete.btn").click((ev) => {
        let delete_url = $(ev.target).attr("data-delete_name");
        last_confirm_url = delete_url;
        delete_config_confirm_modal.find(".repo_name").text(decodeURIComponent(delete_url.replace(/\+/g, ' ')));
        delete_config_confirm_modal.attr("action", "/delete/repo/" + delete_url)
    });

    const preview_modal = $("#preview_modal");
    const pm_repo_name = preview_modal.find(".repo_name");
    const pm_code = preview_modal.find("code");

    preview_modal.find(".modal-close").click((ev) => {
        pm_code.text("Loading...");
        pm_repo_name.text("");
    });

    $(".preview.btn").click((ev) => {
        pm_repo_name.text(decodeURIComponent($(ev.target).attr("data-repo_link")));
        $.ajax({
            type: "POST",
            url: "/preview/" + $(ev.target).attr("data-repo_link"),
            success: function (msg, textStatus, jqXHR) {
                console.log(msg);
                pm_code.text(msg);
            },
            error: function (jqXHR, textErr, err) {
                console.log(textErr);
                console.log(err);
            }
        });
    });

    $(".data_use").find(".progress > .determinate").css("width", used_kilobytes * 100 / total_kilobytes + "%");
});

function service_name_check(self) {
    let obj = $(self);
    if (obj.val().length !== 0 && (obj.attr("value") === obj.val() || !service_names.has(obj.val()))) {
        obj.removeClass("invalid");
        obj.addClass("valid");
        self.setCustomValidity("");
        return true;
    } else {
        obj.removeClass("valid");
        obj.addClass("invalid");
        self.setCustomValidity("Service name already exists");
        return false;
    }
}

function repo_name_check(self) {
    let obj = $(self);
    if (obj.val().length !== 0 && (obj.attr("value") === obj.val() || !repo_names.has(obj.val()))) {
        obj.removeClass("invalid");
        obj.addClass("valid");
        self.setCustomValidity("");
        return true;
    } else {
        obj.removeClass("valid");
        obj.addClass("invalid");
        self.setCustomValidity("Repository name already exists");
        return false;
    }
}
