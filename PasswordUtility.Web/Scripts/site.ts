/// <reference path="typings/jquery/jquery.d.ts" />
class Main {
    validatePassword(password: string): string {
        var resultValue: string;
        $.ajax({
            url: "http://localhost:7128/api/password/validate?password=" + password,
            method: "POST",
            cache: false,
            async: false,
            contentType: "application/json",
            success(result) {
                console.log(result);
                resultValue = result;
            },
            error(request, status, error) {
                console.log(request.responseText);
            }
        });

        return resultValue;
    }
}

$(document).ready(() => {
    var main = new Main();

    $("#btnValidate").on("click", ()=> {
        var passwordToTest :string = $("#ValidatePassword").val();
        var result = main.validatePassword(passwordToTest);
        var validationText = result.toString() + "/100";
        $('#lblValidationResult').text(validationText);
    });
});
     