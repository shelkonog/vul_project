/*!
  *
*/

$(document).ready(function() {
                $('#js-select2-type-soft').select2({
                    allowClear: true,
                    width: "resolve",
                    placeholder: "Выберите тип ПО",
                    language: "ru" });

                $('#js-select2-name').select2({
                    ajax: {
                        url: 'ajax',
                        dataType: "json",
                        type: "GET",
                        data: function (params) {
                        return {
                            q: params.term };
                        },
                     },
                    allowClear: true,
                    closeOnSelect: true,
                    placeholder: "Выберите наименование ПО",
                    minimumInputLength: 3,
                    width  :   'element',
                    language: "ru" });

                $("#js-select2-name").change(function() {
                    var id = $(this).val();
                    $('#js-select2-version').empty();
                    $.ajax({
                        url: 'ajax_ver',
                        dataType: "json",
                        type: "GET",
                        data: {q: id},
                        success: function(resp) {
                            len = resp.results;
                            $('#js-select2-version').select2({
                                placeholder: "Выберите версию ПО",
                                allowClear: true,
                                data: len,
                                disabled: false,
                                tags: false,
                                language: "ru"});
                        },
                        });
                    });

                $('#js-select2-version').select2({
                    placeholder: "Выберите сначала ПО",
                    allowClear: true,
                    disabled: true,
                    tags: false,
                    language: "ru" });

                $('#js-select2-severrety').select2({
                    placeholder: "Выберите уровень опасности",
                    tags: false,
                    allowClear: true,
                    language: "ru" });

                $('#js-select2-year').select2({
                    placeholder: "Выберите год добавления УЯ",
                    tags: false,
                    allowClear: true,
                    language: "ru" });
                });
