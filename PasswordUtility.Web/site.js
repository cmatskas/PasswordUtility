/// <reference path="typings/jquery/jquery.d.ts" />
var Main = (function () {
    function Main() {
    }
    Main.prototype.validatePassword = function (password) {
        var resultValue;
        $.ajax({
            url: "http://localhost:7128/api/password/validate?password=" + password,
            method: "POST",
            cache: false,
            async: false,
            contentType: "application/json",
            success: function (result) {
                console.log(result);
                resultValue = result;
            },
            error: function (request, status, error) {
                console.log(request.responseText);
            }
        });
        return resultValue;
    };
    return Main;
})();
$(document).ready(function () {
    var main = new Main();
    $("#btnValidate").on("click", function () {
        var passwordToTest = $("#ValidatePassword").val();
        var result = main.validatePassword(passwordToTest);
        var validationText = result.toString() + "/100";
        $('#lblValidationResult').text(validationText);
    });
});
//# sourceMappingURL=site.js.map