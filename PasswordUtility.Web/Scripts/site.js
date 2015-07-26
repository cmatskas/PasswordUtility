var Main = (function () {
    function Main() {
    }
    Main.prototype.validatePassword = function (password) {
        var resultValue;
        $.ajax({
            url: "/api/password/validate?password=" + password,
            method: "POST",
            cache: false,
            async: true,
            dataType: "application/json",
            success: function (result) {
                console.log(result);
                resultValue = result;
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