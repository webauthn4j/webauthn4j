$ = require('jquery');
jQuery = $;

Config = require('lib/config.js');

// UpdateViewModel constructor
let AuthorityUpdateViewModel = function(){
    let _this = this;
    $(document).ready(function() {
        //対応するViewがDOMに存在する場合
        if($('#authority-update-view').length){
            _this.setupEventListeners();
        }
    });
};

AuthorityUpdateViewModel.prototype.searchCandidateUsers = function () {
    let input = $('#user-search-input').val();
    let url = Config.joinPaths(Config.CONTEXT_PATH, "/api/admin/authorities/listCandidateUsers");
    $.ajax({
        url: url,
        data: {
            keyword: input
        },
        dataType: 'json'
    }).then(function(data) {

        let userIds = $('#user-list input[name=users]').map(function(_, item){
            return parseInt(item.value, 10);
        }).get();
        let items = data.content.filter(function(item) {
            return $.inArray(item.id, userIds) === -1; // リストに存在しない要素のみを残す
        });

        $('#candidate-user-list').empty();
        $.each(items, function(index, item){
            let tr = $('<tr class="user-item"></tr>');
            tr.append(
                $('<td></td>').append(
                    $('<span></span>').text(
                        item.id
                    )
                ).append(
                    $('<span>.</span>')
                ).append(
                    $('<input type="hidden" name="users" disabled="disabled" />').val(
                        item.id
                    )
                )
            );
            tr.append(
                $('<td></td>').append(
                    $('<span></span>').text(
                        item.fullname
                    )
                )
            );
            let button = $('<button type="button" class="btn btn-box-tool plus-button"><i class="fa fa-plus"></i></button>');
            button.on('click', function(){
                let userItem = $(this).closest('tr.user-item');
                let removeButton = $('<button type="button" class="btn btn-box-tool remove-button"><i class="fa fa-remove"></i></button>');
                removeButton.on('click', function (e) {
                    $(e.target).closest('tr.user-item').remove();
                });
                userItem.find("input[type=hidden]").prop('disabled', false);
                $(this).replaceWith(removeButton);
                $('#user-list').append(userItem);
            });
            tr.append(
                $('<td></td>').append(
                    button
                )
            );
            $('#candidate-user-list').append(tr);
        });
    });
};

AuthorityUpdateViewModel.prototype.searchCandidateGroups = function () {
    let input = $('#group-search-input').val();
    let url = Config.joinPaths(Config.CONTEXT_PATH, "/api/admin/authorities/listCandidateGroups");
    $.ajax({
        url: url,
        data: {
            keyword: input
        },
        dataType: 'json'
    }).then(function(data) {

        let groupIds = $('#group-list input[name=groups]').map(function(_, item){
            return parseInt(item.value, 10);
        }).get();
        let items = data.content.filter(function(item) {
            return $.inArray(item.id, groupIds) == -1; // リストに存在しない要素のみを残す
        });

        $('#candidate-group-list').empty();
        $.each(items, function(index, item){
            var tr = $('<tr class="group-item"></tr>');
            tr.append(
                $('<td></td>').append(
                    $('<span></span>').text(
                        item.id
                    )
                ).append(
                    $('<span>.</span>')
                ).append(
                    $('<input type="hidden" name="groups" disabled="disabled" />').val(
                        item.id
                    )
                )
            );
            tr.append(
                $('<td></td>').append(
                    $('<span></span>').text(
                        item.groupName
                    )
                )
            );
            let button = $('<button type="button" class="btn btn-box-tool plus-button"><i class="fa fa-plus"></i></button>');
            button.on('click', function(){
                let groupItem = $(this).closest('tr.group-item');
                let removeButton = $('<button type="button" class="btn btn-box-tool remove-button"><i class="fa fa-remove"></i></button>');
                removeButton.on('click', function () {
                    $(this).closest('tr.group-item').remove();
                });
                $(this).replaceWith(removeButton);
                groupItem.find("input[type=hidden]").prop('disabled', false);
                $('#group-list').append(groupItem);
            });
            tr.append(
                $('<td></td>').append(
                    button
                )
            );
            $('#candidate-group-list').append(tr);
        });
    });
};

AuthorityUpdateViewModel.prototype.setupEventListeners = function () {
    let _this = this;
    $('#user-search-input').on('keypress', function(e){
        _this.searchCandidateUsers();
        if (e.keyCode == '13') {
            e.preventDefault();
        }
    });
    $('#user-list .remove-button').on('click', function(){
        $(this).closest('tr.user-item').remove();
    });

    $('#group-search-input').on('keypress', function(e){
        _this.searchCandidateGroups();
        if (e.keyCode == '13') {
            e.preventDefault();
        }
    });
    $('#group-list .remove-button').on('click', function(){
        $(this).closest('tr.group-item').remove();
    });
};

module.exports = new AuthorityUpdateViewModel();
