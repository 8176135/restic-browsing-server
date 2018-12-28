const list = $("#list");
const edit_repo_modal = $("#edit_repo_modal");
list.find("input")
    .each((i, c) => $(c).prop("checked", false).prop("indeterminate", false));
list.on("change", "input",
    function (e) {
        let self = $(this);
        checkAllChildren(self, this.checked);
        if (this.checked) {
            makeParentTrue(self);
        } else {
            makeParentFalse(self);
        }
    });

$(".data_use").find(".progress > .determinate").css("width", used_kilobytes * 100 / total_kilobytes + "%");

function checkAllChildren(checkbox, isChecked) {
    checkbox.parent().siblings("ul").find("input").prop("checked", isChecked).prop("indeterminate", false);
}

function makeParentTrue(checkbox) {
    let makeTrue = true;
    let items =  checkbox.parent().parent().siblings().children("label").children("input");

    for (let i = 0; i < items.length; i++) {
        if (!items[i].checked || $(items[i]).prop("indeterminate")) {
            makeTrue = false;
            break;
        }
    }

    if (makeTrue) {
        let curCheck =  checkbox.parent().parent().parent().siblings("label").children("input");
        if (curCheck.length) {
            curCheck.prop("indeterminate", false);
            curCheck.prop("checked", true);
            makeParentTrue(curCheck);
        }
    } else {
        makeParentIndeterminate(checkbox);
    }
}

function makeParentFalse(checkbox) {
    let makeFalse = true;
    let items = checkbox.parent().parent().siblings().children("label").children("input");

    for (var i = 0; i < items.length; i++) {
        if (items[i].checked || $(items[i]).prop("indeterminate")) {
            makeFalse = false;
            break;
        }
    }

    if (makeFalse) {
        let curCheck = checkbox.parent().parent().parent().siblings("label").children("input");
        if (curCheck.length) {
            curCheck.prop("indeterminate", false);
            curCheck.prop("checked", false);
            makeParentFalse(curCheck);
        }
    } else {
        makeParentIndeterminate(checkbox);
    }
}

function makeParentIndeterminate(checkbox) {
    let item = checkbox.parent().parent().parent().siblings("label").children("input");
    if (item.length) {
        item.prop("indeterminate", true);
        item.prop("checked", false);
        makeParentIndeterminate(item);
    }
}

function download() {
    let files_to_download = [];

    getChildCheckbox($("#list").children("li").children("label").children("input"), files_to_download);

    if (files_to_download.length === 0) {
        return;
    }

    $(".btn.download").addClass("invisible");
    $(".progress.download").removeClass("invisible");

    $.ajax({
        type: "POST",
        data: JSON.stringify(files_to_download),
        contentType: "application/json; charset=utf-8",
        xhrFields: {
            responseType: 'blob'
        },
        url: encodeURIComponent($("#repo_name").text()) + "/download",
        success: function (msg, textStatus, jqXHR) {
            console.log(msg);
            msg.type = 'application/zip';
            // let blob = new Blob([msg], { type: 'application/octet-stream' });
            let link = document.createElement('a');
            link.href = window.URL.createObjectURL(msg);
            link.download = "YourFilesIn-" + repo_name + ".zip";
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        },
        error: function (jqXHR, textErr, err) {
            console.log(textErr);
            console.log(err);

        }
    });
}

function getChildCheckbox(parentCheck, tally) {
    let list_of_boxes = parentCheck.parent().siblings("ul").children("li").children("label").children("input");
    let indert_boxes = list_of_boxes.filter((i, c) => {
        return $(c).prop("indeterminate");
    });
    let checked_boxes = list_of_boxes.filter((i, c) => {
        return c.checked && !$(c).prop("indeterminate");
    });
    for (let i = 0; i < checked_boxes.length; i++) {
        let folder_num = $(checked_boxes[i]).attr("data-folder-num");
        if (folder_num) {
            tally.push(+folder_num);
        } else {
            getChildCheckbox($(checked_boxes[i]), tally);
        }
    }
    for (let i = 0; i < indert_boxes.length; i++) {
        getChildCheckbox($(indert_boxes[i]), tally);
    }
}

list.bonsai({
    expandAll: false, // expand all items
    expand: null, // optional function to expand an item
    collapse: null, // optional function to collapse an item
    addExpandAll: false, // add a link to expand all items
    addSelectAll: false, // add a link to select all checkboxes
    selectAllExclude: null, // a filter selector or function for selectAll
    idAttribute: 'id', // which attribute of the list items to use as an id

    // createInputs: create checkboxes or radio buttons for each list item
    // using a value of "checkbox" or "radio".
    //
    // The id, name and value for the inputs can be declared in the
    // markup using `data-id`, `data-name` and `data-value`.
    //
    // The name is inherited from parent items if not specified.
    //
    // Checked state can be indicated using `data-checked`.
    createInputs: false,
    // checkboxes: run qubit(this.options) on the root node (requires jquery.qubit)
    checkboxes: false,
    // handleDuplicateCheckboxes: update any other checkboxes that
    // have the same value
    handleDuplicateCheckboxes: false
});