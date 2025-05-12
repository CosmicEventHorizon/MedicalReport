document.addEventListener("DOMContentLoaded", function () {
	const signupForm = document.querySelector("form");
	signupForm.addEventListener("submit", function (event) {
		event.preventDefault();

		const formData = new FormData(signupForm);

		fetch("/login", {
			method: "POST",
			body: formData,
		})
			.then((response) => {
				if (response.status === 202) {
					window.location.href = "/";
				} else {
					alert("Username or Password is wrong");
				}
			})
			.catch((error) => {
				console.error("Error during login:", error);
				alert("An error occurred. Please try again later.");
			});
	});
});
