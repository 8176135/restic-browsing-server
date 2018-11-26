// $(".edit").click((ev) => {
//     //$("#edit_repo_modal").modal();
//
//     console.log($(ev.target).attr("data-for"));
// });

$(document).ready(function(){
    $('.modal').modal();
    $('.message_popup').modal("open");

    $('.repo_name').click((ev) => {
        let line = $(ev.target).parents(".line");
        line.hide();
        line.parents(".collection-item").find(".progress").removeClass("invisible");
    });
});
